# CICD-SEC-7: Insecure System Configuration - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Misconfigurations](#chaining-misconfigurations)

## Understanding the Attack Surface

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can find and fix these issues in CI/CD systems you own or are explicitly authorised to test.

Insecure system configuration is rarely exploited with a clever payload. It is exploited through **reconnaissance and access**: an attacker locates a build or SCM system, reads what it volunteers about its version and posture, and walks through whichever door—anonymous access, an unpatched plugin, an open script console—was left open. Because the flaws live in settings and patch levels rather than application logic, they are cheap to find at internet scale.

The attacker's objective at this layer is usually one of:

- Reach a control surface that should never have been public (build console, script console, SCM admin, registry API).
- Turn a known-vulnerable server or plugin version into code execution on the controller.
- Land on a shared or over-privileged runner and harvest the secrets and cloud roles the pipeline holds.
- Forge an input the system trusts (an unauthenticated webhook) to drive the pipeline.

### Core Attack Flow

```
1. Discover
   |
   Find exposed consoles/APIs via scanners, DNS, certificate transparency
2. Fingerprint
   |
   Read version banners (X-Jenkins), plugin lists, /systemInfo, login page
3. Enter
   |
   Anonymous access, default creds, vulnerable plugin, or open script console
4. Execute / Harvest
   |
   Run code on controller/runner, read stored credentials and job config
5. Escalate / Persist / Tamper
   |
   Pivot to production and cloud, add plugins/jobs, inject into builds
```

## Common Attack Patterns

### 1. Locating Exposed CI/SCM Consoles

Attackers enumerate management planes that were never meant to be public.

```
# Internet-wide search fingerprints (illustrative):
title:"Dashboard [Jenkins]"          # exposed Jenkins controllers
http.favicon.hash:<jenkins-hash>
X-Jenkins header present on :8080
/-/health, /users/sign_in            # self-managed GitLab instances
/v2/_catalog                         # open container registry catalog
```

**Payoff**: a target list of management planes to probe—before any authentication is even attempted.

### 2. Version and Plugin Fingerprinting

The controller advertises exactly what to exploit.

```
HTTP/1.1 200 OK
X-Jenkins: 2.2xx.x                   # exact core version
X-Jenkins-Session: ...
# Plugin manager and update pages reveal installed plugins and versions:
GET /pluginManager/api/json?depth=1  # names + versions of every plugin
```

**Payoff**: the exact core and plugin versions are matched to published advisories—exploitation by catalogue, no probing required.

### 3. Anonymous or Default Access

Authorization left open, or credentials never changed.

```
# Anonymous read exposes job config, build logs, and sometimes secrets:
GET /job/deploy-prod/config.xml      # pipeline definition, embedded values
GET /job/deploy-prod/1/consoleText   # build log (may echo secrets)

# Or a guessable/default admin login:
POST /j_spring_security_check  j_username=admin&j_password=admin
```

**Payoff**: read (and often write) access to the build plane with no exploit at all.

### 4. Script Console to Remote Code Execution

An administrative script console reachable by the attacker is direct code execution on the controller.

```
# Jenkins Groovy console (requires reaching /script with sufficient rights):
POST /script
script=println "id".execute().text        # runs a command on the controller

# The same surface can read stored credentials and the filesystem.
```

**Payoff**: arbitrary code on the build controller—the highest-value foothold in the pipeline.

### 5. Exploiting a Vulnerable Plugin or Unpatched Core

Plugins are unreviewed code running inside the controller; an outdated one with an advisory is exploited as-is.

```
Vulnerable-plugin classes commonly seen in advisories:
- missing permission checks  -> unauthenticated access to sensitive actions
- path traversal             -> read arbitrary files (secrets, config) off the controller
- unsafe deserialization     -> remote code execution
- SSRF via build steps       -> reach cloud metadata / internal services
```

**Payoff**: file read, auth bypass, or RCE using a known exploit against the exact version advertised.

### 6. Harvesting Secrets from the Build System

Once inside, the CI system's own stores are the prize.

```
# Credentials the controller manages, environment, and job definitions:
GET /credentials/                    # stored credential IDs and scopes
GET /systemInfo                      # environment variables, versions
# Verbose/debug builds echo secrets straight into the log:
+ curl -H "Authorization: Bearer ****" ...   # unmasked when debug is on
```

**Payoff**: deploy credentials, cloud roles, registry tokens, and signing material—the keys to everything downstream.

### 7. Compromising a Shared / Over-Privileged Runner

Runners that are long-lived, shared, and broadly permissioned are a soft target.

```
# From code executing on a non-ephemeral shared runner:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/  # cloud role
cat /home/runner/work/**/.git-credentials                                 # leftover creds
# Persist for the next job:
echo 'exfil hook' >> ~/.bashrc
```

**Payoff**: the runner's cloud role, secrets from subsequent jobs, and lateral movement across a flat network.

### 8. Forged / Permissive Webhooks

An unauthenticated webhook endpoint is an unauthenticated trigger into the pipeline.

```
POST /github-webhook/ HTTP/1.1       # no signature verification
X-GitHub-Event: push
{ "ref": "refs/heads/main", "repository": { ... } }   # forged event triggers a build
```

**Payoff**: attacker-controlled build/deploy triggers, and abuse of any over-scoped integration token the webhook path exercises.

### 9. Cleartext / Weak Transport

Consoles served over plain HTTP or with ignored certificate errors expose credentials in transit.

```
http://jenkins.example.com:8080/     # login and session over cleartext
- expired/self-signed cert clicked through by agents
- agent-to-controller traffic unencrypted on a shared network
```

**Payoff**: interception of session cookies, agent secrets, and admin credentials by anyone on-path.

## Chaining Misconfigurations

Individually modest weaknesses combine into full compromise of the build plane:

```
Exposed console (internet-reachable)   -> locate the controller
        +
Version banner + plugin list           -> pick a matching published advisory
        +
Vulnerable plugin / open script console -> code execution on the controller
        =  full control of the CI system, no application bug required
```

Another common chain, from the pipeline outward:

```
Shared over-privileged runner          -> code runs with a broad cloud role
        -> read 169.254.169.254 metadata credentials
        -> harvest next job's secrets from the shared host
        -> pivot across a flat network to production
```

And a trust-abuse chain:

```
Unauthenticated webhook                -> forge a push/deploy event
        -> trigger a build on an unpatched controller
        -> debug mode echoes secrets into the public build log
        =  credential theft with no console access at all
```

## Key Takeaways

1. **The management plane is the target**—exposed consoles and APIs are located and probed before any exploit is attempted.
2. **The system tells the attacker how to attack it**—version banners and plugin lists are free reconnaissance; silence them and lock them down.
3. **Plugins and script consoles are RCE waiting to happen**—unreviewed plugin code and admin consoles are the highest-value footholds.
4. **Runners are attack surface, not just workers**—shared, long-lived, over-privileged runners leak secrets and enable lateral movement.
5. **Small issues chain**—exposure plus a version banner plus one unpatched plugin equals full control of the build plane.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build a repeatable hardening baseline for CI/CD systems
- **[Configuration Examples](examples.md)**: See insecure vs. secure settings for SCM, CI, and runners
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP Top 10 CI/CD Security Risks lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
