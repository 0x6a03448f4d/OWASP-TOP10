# CICD-SEC-7: Insecure System Configuration - Prevention

## Prevention Strategy Overview

Preventing insecure system configuration is less about one control and more about **treating the CI/CD plane as production infrastructure** and making a hardened state the only state that runs:

1. Patch the CI/SCM systems and their plugins promptly and continuously.
2. Keep the management plane off the public internet and behind strong authentication.
3. Minimise the plugin and integration surface to the vetted essentials.
4. Isolate runners: ephemeral, least-privilege, off flat/production networks.
5. Harden per a vendor benchmark, codify it, and detect drift.

### Core Principles

- **The pipeline is production**: apply the same patching, exposure, and identity discipline you apply to production services.
- **Secure by default**: anonymous access off, debug off, TLS on—opting out of a control should be explicit and rare.
- **Least functionality**: every plugin, integration, open port, and standing runner is attack surface; remove what you do not need.
- **Repeatable, not hand-tuned**: codify configuration against a benchmark so it is identical everywhere and reviewable in version control.

## 1. Patch CI/SCM Systems and Plugins Promptly

Unpatched controllers and outdated plugins are the most-published CI compromise class. Make updating routine, not heroic.

```bash
# Track and apply core + plugin updates on a cadence, not ad hoc:
- subscribe to the vendor security advisory feed (Jenkins, GitLab, TeamCity)
- schedule a regular patch window for controller core and plugins
- test updates in a staging controller, then promote
- record installed versions so exposure to a new advisory is answerable in minutes

# Jenkins: audit installed plugins and available updates via CLI/API
curl -s https://ci.internal/pluginManager/api/json?depth=1 \
  | jq '.plugins[] | {shortName, version, hasUpdate}'
```

> Prefer a controller you can rebuild from configuration over one you patch in place—an immutable, reproducible controller makes patching a redeploy rather than a risky live upgrade.

## 2. Minimise the Plugin and Integration Surface

The safest plugin is the one that isn't installed. Each plugin is code running inside the controller with its privileges.

```
# Plugin hygiene:
- remove every plugin not actively used
- vet new plugins for maintenance status and provenance before installing
- pin plugin versions; update deliberately, not automatically from arbitrary sources
- prefer official/first-party integrations over unmaintained community ones
- review the plugin inventory on a schedule and prune

# Integrations (webhooks, cloud connectors, chat/bots):
- grant each the minimum scope it needs, nothing broader
- remove integrations for tools you no longer use
```

## 3. Keep the Management Plane Off the Public Internet

Consoles and APIs are for operators, not the world. Put them behind the network perimeter.

```nginx
# Network placement:
- CI/SCM consoles reachable only via VPN or a corporate IP allow-list
- agent/controller ports (e.g. Jenkins :50000) never exposed publicly
- registry and orchestrator APIs restricted to known networks

# Example nginx allow-list in front of a controller:
location / {
    allow 10.0.0.0/8;          # corporate/VPN range
    allow 192.0.2.10/32;       # bastion
    deny  all;
    proxy_pass http://127.0.0.1:8080;
}
```

## 4. Enforce Strong Authentication on Every Admin Surface

Anonymous access and shared logins have no place on a build plane.

```
# Identity and access:
- disable anonymous access entirely (no anonymous read/build/configure)
- integrate SSO (SAML/OIDC) so accounts are centrally governed
- require MFA for all administrative access
- remove default/sample accounts; no shared admin credentials
- apply matrix/role-based authorization with least privilege per job/folder

# Jenkins: avoid "Anyone can do anything"; use a matrix strategy where
# Anonymous has NO permissions and rights are granted per authenticated role.
```

## 5. Disable Script Consoles, Debug, and Verbose Modes in Production

Remove the surfaces that turn a foothold into code execution or secret disclosure.

```yaml
# Remove or restrict dangerous surfaces:
- restrict the script/Groovy console to a tiny set of break-glass admins,
  audited, and unreachable by normal users
- disable in-product dev consoles (e.g. embedded DB consoles) in production
- turn OFF debug/verbose pipeline logging in production runs
- mask secrets in logs and forbid echoing credentials in build steps

# GitLab CI: never set debug tracing in shared/production pipelines
# (CI_DEBUG_TRACE exposes masked variables in job logs)
variables:
  CI_DEBUG_TRACE: "false"
```

## 6. Secure and Isolate Self-Hosted Runners

Treat runners as disposable, least-privilege workers—never durable pets.

```
# Runner hardening:
- make runners ephemeral: fresh, single-use VM/container per job, destroyed after
- never share a runner between trusted and untrusted (fork/PR) workloads
- attach the minimum cloud role; block access to the metadata endpoint where unused
- place runners on an isolated network segment, not flat with production
- do not run builds as root; drop privileges and use rootless containers

# GitHub Actions: isolate and scope self-hosted runners
- use ephemeral runners (--ephemeral) that de-register after one job
- do NOT enable self-hosted runners for public-repo fork PRs
```

## 7. Enforce TLS Everywhere

No cleartext consoles, no ignored certificate errors, no unencrypted agent traffic.

```nginx
# Transport:
- serve every console and API over HTTPS with a valid, trusted certificate
- redirect HTTP to HTTPS; disable plain-HTTP listeners
- encrypt controller-to-agent traffic; verify agent certificates
- automate certificate issuance/renewal (ACME) so certs never silently expire

server { listen 80; return 301 https://$host$request_uri; }
ssl_protocols TLSv1.2 TLSv1.3;
```

## 8. Validate and Restrict Webhooks

A webhook endpoint is an untrusted input into your pipeline—authenticate it.

```
# Webhook hardening:
- require a shared secret and verify the HMAC signature on every event
- allow-list the source IP ranges of the SCM/provider
- accept only the event types you actually handle
- scope any token the webhook path uses to the minimum needed

# GitHub example: verify X-Hub-Signature-256 against a per-hook secret
sig = hmac_sha256(secret, raw_body)
if not constant_time_equal(sig, header_signature): reject(401)
```

## 9. Harden to a Benchmark and Codify Configuration

Adopt a documented baseline (vendor hardening guide / CIS-style benchmark) and apply it as code so it is identical everywhere.

```yaml
# cicd-hardening-baseline.yaml (excerpt) — versioned, applied by automation
scm:
  public_exposure: false
  sso_required: true
  mfa_required: true
ci_controller:
  anonymous_access: false
  script_console: break_glass_only
  plugins_pinned: true
  debug_logging: false
  tls_required: true
runners:
  ephemeral: true
  privileged: false
  isolated_network: true
  metadata_access: denied_by_default
webhooks:
  signature_verification: required
  source_allow_list: true
```

Apply it with configuration-as-code tooling (for example Jenkins Configuration-as-Code / JCasC, Terraform for SCM and cloud, Kubernetes manifests for runners) so the intended secure state is reviewable and reproducible.

## 10. Detect Drift and Monitor the Build Plane

Hand-tuned systems regress. Automate the check and watch for the signatures of probing.

```
# Continuous checks:
- scan controller config against the benchmark on a schedule; fail on drift
- alert when a new plugin is installed, a role changes, or debug is enabled
- alert on requests to sensitive paths from unexpected sources:
  SENSITIVE = ('/script', '/systemInfo', '/pluginManager', '/credentials')
- watch for new listening ports and console access from new IPs
- log and review admin actions on the CI/SCM systems
```

## Hardening Checklist by System

| System | Do | Avoid |
|--------|----|-------|
| SCM (GitHub/GitLab/Bitbucket) | SSO+MFA, private exposure, least-privilege orgs | Public console, open sign-up, broad default roles |
| CI server (Jenkins/TeamCity) | Patch core+plugins, no anonymous, restrict script console | Outdated plugins, "anyone can do anything", open /script |
| Runners/agents | Ephemeral, isolated, least-privilege, non-root | Shared long-lived runners, broad cloud roles, flat network |
| Registry/orchestrator | Auth required, private API, TLS, scoped tokens | Open catalog, anonymous pull/push, cleartext |
| Network/transport | VPN/allow-list, TLS everywhere, valid certs | Public consoles, plain HTTP, ignored cert errors |

## Key Takeaways

1. **Patch relentlessly** — unpatched cores and outdated plugins are the most common CI-compromise class.
2. **Hide the management plane** — VPN/allow-list plus SSO+MFA keeps consoles and APIs off the attacker's map.
3. **Cut the surface** — fewer plugins, fewer integrations, no script console for normal users.
4. **Isolate runners** — ephemeral, least-privilege, segmented workers stop one build from poisoning the next.
5. **Codify and watch** — harden to a benchmark as code and detect drift, because hand-tuned systems silently regress.

## Next Steps

- **[Configuration Examples](examples.md)**: Insecure vs. secure settings for SCM, CI, and runners
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP Top 10 CI/CD Security Risks lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
