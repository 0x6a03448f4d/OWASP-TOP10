# CICD-SEC-8: Ungoverned Usage of 3rd Party Services - Prevention

## Prevention Strategy Overview

Preventing this risk is less about any single control and more about **replacing frictionless, permanent trust with a governed lifecycle**:

1. Know what you have—maintain an inventory of every third-party integration.
2. Gate what gets added—require approval and security review to onboard.
3. Grant the minimum—least-privilege scopes, short-lived where possible.
4. Pin and allow-list executable components—immutable references, org policy.
5. Review and revoke continuously—access has an expiry, not a lifetime.
6. Monitor and contain—log third-party activity and limit blast radius.

### Core Principles

- **Govern the lifecycle, not the moment**: onboarding, scoping, review, and offboarding are all required—authorizing once is not governance.
- **Least privilege by default**: every scope, repo, and permission a third party holds is attack surface—grant the minimum and read-only where possible.
- **Immutable and allow-listed**: anything that executes in your pipeline is pinned to a commit and permitted by explicit policy.
- **Assume breach**: design so that a compromise of any single third party is contained, detected, and recoverable.

## 1. Build and Maintain an Inventory

You cannot govern what you cannot see. Enumerate every external identity with access and give each a named owner and a reason to exist.

```yaml
# third-party-inventory.yaml (excerpt) — reviewed, versioned, owned
integrations:
  - name: coverage-uploader
    type: saas-token
    owner: platform-team
    scope: "single repo: web-app; upload endpoint only"
    credential: short-lived OIDC (no stored PAT)
    added: 2026-01-10
    review_by: 2026-07-10
  - name: pr-quality-bot
    type: scm-app
    owner: dev-experience
    scope: "read: contents, pull_requests; repos: web-app, api"
    review_by: 2026-07-10
policy:
  every_entry_must_have: [owner, scope, review_by]
  unlisted_integrations: "denied by org policy"
```

Reconcile the inventory against the platform's actual authorized-Apps / OAuth-grants / deploy-keys / webhooks lists on a schedule, and flag anything present in the platform but missing from the inventory.

## 2. Approval and Security Review to Onboard

Make adding a new integration a deliberate, reviewed act rather than a one-click default.

```
New-integration checklist (gate before any grant is issued):
  [ ] Who is the vendor/author, and what is their security posture?
  [ ] What is the MINIMUM scope needed for the stated feature?
  [ ] Can it be read-only? Can it be limited to specific repositories?
  [ ] Can we use short-lived / OIDC credentials instead of a stored token?
  [ ] Who owns it, and when is its next review?
  [ ] What is the blast radius if this vendor is breached?
```

Restrict who can authorize third-party Apps/OAuth in the org so approval cannot be bypassed by any individual developer.

## 3. Least-Privilege Scopes for Apps, OAuth, and Tokens

Grant the narrowest access that works—specific repositories, minimal permissions, read-only wherever the feature allows.

```yaml
# WRONG: org-wide, read/write, "to be safe"
scope:
  repositories: all
  contents: read-write
  members: read

# RIGHT: exactly what the feature needs
scope:
  repositories: [web-app]        # only the repo it serves
  contents: read                 # read-only scanner needs no write
  metadata: read
  # nothing else
```

Prefer short-lived, workload-scoped credentials over long-lived personal access tokens. Where the platform supports OIDC federation, exchange a per-run identity token for temporary cloud credentials so no static secret is ever stored with a third party.

## 4. Pin Third-Party Actions and Plugins by Commit SHA

A tag or branch is mutable and can be repointed to malicious code. A full commit SHA is immutable—pin to it.

```yaml
# WRONG: mutable references you do not control
- uses: some-user/awesome-action@v2
- uses: another/step@main

# RIGHT: pinned to a full commit SHA (with a comment noting the version)
- uses: some-user/awesome-action@3f1c0a9d6b2e4f8a1c7d5e2b9f0a4c6d8e1b3a5c  # v2.3.1
- uses: another/step@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0        # v1.0.4
```

Update pins deliberately (via a dependency-update bot that proposes the new SHA in a reviewable PR), and prefer verified/first-party components over anonymous ones. Vendor critical third-party Actions into a repository you control when you need full change control.

## 5. Restrict Which Components May Run (Org Policy)

Do not allow every Action or marketplace app in the world to execute. Constrain the set at the org level.

```yaml
# Org policy intent (platform-specific settings):
allowed_actions: selected            # not "all"
allow:
  - "actions/*@*"                    # first-party
  - "our-org/*@*"                    # internal, trusted
  - "verified-creator/tool@<sha>"    # explicitly reviewed + pinned
deny_by_default: true                # anything not listed cannot run

marketplace_apps:
  installation: "org-admin approval required"
  third_party_by_default: denied
```

Combine this with restricting who can install Apps and who can change the allow-list, so the policy cannot be quietly widened.

## 6. Periodic Access Review and Revocation

Access should expire by default. Review on a schedule and remove anything unused, unowned, or stale.

```python
# Quarterly review job (illustrative): flag grants that are stale or unused
def review_integrations(inventory, platform_grants, activity_log):
    for grant in platform_grants:
        if grant.id not in inventory:
            flag(grant, "UNINVENTORIED - investigate and remove")
        if grant.last_used is None or grant.last_used < ninety_days_ago():
            flag(grant, "UNUSED 90d - candidate for revocation")
        if grant.owner_left_company:
            flag(grant, "ORPHANED - reassign or revoke")
        if grant.review_by < today():
            flag(grant, "REVIEW OVERDUE")
```

Tie integration ownership to the offboarding process so that when a person or project goes away, their grants, tokens, and bots are revoked—not left behind.

## 7. Govern Webhooks and Data Flows

- **Verify inbound webhooks**: require and check a signature/secret on every inbound webhook before it can trigger any pipeline action; reject unsigned or replayed events.
- **Constrain outbound data**: never send secrets or full environments in outbound webhook payloads; send the minimum, to an approved endpoint only.
- **Inventory webhooks**: treat each webhook as a governed integration with an owner and a review date, and alert on newly created ones.

```python
# Verify an inbound webhook signature before acting on it
import hmac, hashlib

def verify(secret: bytes, body: bytes, provided_sig: str) -> bool:
    expected = 'sha256=' + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_sig)   # constant-time compare
# If verify() is False: reject. No trigger, no deploy.
```

## 8. Limit Blast Radius (Assume the Third Party Is Breached)

Design so that compromising any one third party cannot reach everything.

- **Scope secrets to jobs**: expose a secret only to the job that needs it, not to every job the third party can influence.
- **Isolate untrusted execution**: run third-party steps in least-privileged runners without production credentials in scope.
- **Separate build from deploy**: keep deploy credentials out of any job where third-party code executes; hand off artifacts, not keys.
- **Short-lived everything**: prefer per-run OIDC tokens so a leaked credential expires in minutes, not years.

## 9. Monitor Third-Party Activity

Make third-party actions visible so abuse does not blend into normal automation.

```python
# Alert on high-signal third-party events
WATCH = [
  "oauth_grant.created", "app.installed", "deploy_key.created",
  "webhook.created", "pat.created_with_broad_scope",
  "integration.wrote_workflow_file", "integration.accessed_new_repo",
]

def on_audit_event(evt):
    if evt.type in WATCH:
        alert(f"3rd-party event: {evt.type} by {evt.actor} on {evt.target}")
    if evt.type == "repo.clone" and evt.actor.is_integration and evt.repo_new_for_actor:
        alert(f"Integration {evt.actor} cloned a repo it never touched before")
```

Also alert on: a token used from a new IP/geography, an integration suddenly touching many repos, and any grant or webhook created outside the approval process.

## 10. Prefer First-Party and Verified, Minimize Count

- Every integration is standing risk—periodically ask whether each is still worth it, and remove marginal ones.
- Prefer first-party/official components and verified publishers over anonymous marketplace entries.
- Consolidate overlapping tools so you govern a small, well-understood set rather than a sprawling long tail.

## Governance Model at a Glance

| Lifecycle stage | Control | What it prevents |
|-----------------|---------|------------------|
| Discover | Inventory + reconciliation | Unknown, unowned access |
| Onboard | Approval + security review | Unvetted vendors and over-scoping |
| Grant | Least-privilege, short-lived, OIDC | Broad, standing credentials |
| Execute | SHA pinning + org allow-list | Malicious/hijacked components |
| Operate | Monitoring + blast-radius limits | Silent abuse, wide cascades |
| Offboard | Periodic review + revocation | Stale, forgotten grants |

## Key Takeaways

1. **Inventory first** — a complete, owned list of who-has-access is the foundation of every other control.
2. **Gate onboarding** — approval and security review stop over-scoped, unvetted integrations before they exist.
3. **Least privilege and short-lived** — narrow scopes and OIDC credentials shrink what any grant is worth.
4. **Pin and allow-list** — immutable SHAs and org policy keep malicious or hijacked components out of your runners.
5. **Review, monitor, and assume breach** — revoke the stale, watch the active, and contain the blast radius of the inevitable vendor compromise.

## Next Steps

- **[Code Examples](examples.md)**: Ungoverned vs. governed integrations side by side
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue with the rest of the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
