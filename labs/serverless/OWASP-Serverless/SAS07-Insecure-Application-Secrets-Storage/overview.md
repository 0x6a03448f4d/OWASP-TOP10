# SAS-7: Insecure Application Secrets Storage - Overview

## Table of Contents
- [What is Insecure Application Secrets Storage?](#what-is-insecure-application-secrets-storage)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insecure Application Secrets Storage?

**Insecure Application Secrets Storage** occurs when the many secrets a serverless function needs to do its job—database credentials, third-party API keys, signing keys, OAuth client secrets, session tokens, encryption keys—are kept somewhere that is convenient for the developer but readable by an attacker. The function may be otherwise well written, but its secrets sit in plaintext environment variables, hardcoded in source committed to Git, baked into the deployment artifact, or written into the infrastructure-as-code that lives in the repository. It is not a single leaked password; it is the accumulated habit of treating secrets as ordinary configuration.

Serverless makes this weakness both more likely and more damaging. A serverless application is not one process with one config file—it is **dozens of small functions**, each of which needs credentials to talk to a database, a queue, a payment provider, or another function. The path of least resistance is to paste those values into `serverless.yml` or a Lambda environment variable and move on. Because functions are **ephemeral and numerous**, secrets get copied widely, shared across functions that should not have them, and are almost never rotated. And because everything is **defined as code**, a plaintext secret in a template is one `git push` away from being permanent, public history.

### Core Concept

```
Secure Secrets Handling:
  Storage     -> managed secret store (Secrets Manager / SSM SecureString), KMS-encrypted
  Delivery    -> fetched at runtime by a least-privilege role, cached in memory
  Code / Git  -> no secret values anywhere in source, config, or history
  Artifact    -> deployment package contains code only, never credentials
  Scope       -> each function reads only the specific secrets it needs
  Rotation    -> secrets rotated automatically; leaked values expire quickly
  Logs        -> secrets redacted; never printed to CloudWatch

Insecure Secrets Handling:
  Storage     -> plaintext environment variables set at deploy time
  Delivery    -> baked in; visible to the console, the API, and every dependency
  Code / Git  -> API keys hardcoded and committed; live forever in history
  Artifact    -> .env files and config with real credentials zipped into the package
  Scope       -> one shared secret handed to every function "just in case"
  Rotation    -> static, long-lived keys that no one has ever changed
  Logs        -> whole event / process.env dumped into logs on error
```

### Why It's Critical for Serverless

Serverless concentrates several conditions that make insecure secret storage especially dangerous:

- Functions are **configuration-driven**, and environment variables are the obvious place to put configuration—so secrets land there by default, in plaintext, visible to anyone who can read the function's config.
- Applications are **defined entirely as code** (`serverless.yml`, SAM/CloudFormation templates), so a secret typed into a template is committed to version control and often pushed to a shared or public repository.
- There are **many small functions**, so a single copied secret spreads across the codebase, and the same value is reused far beyond the one place it belongs.
- Functions run **arbitrary third-party dependencies** in the same process as your secrets; any of that code can read `process.env` / `os.environ` and exfiltrate it (ties to SAS-6 and SAS-10).
- The platform makes secrets **easy to read after the fact**: anyone with `lambda:GetFunctionConfiguration`, or access to the console, or to an exception dump, sees plaintext environment variables directly.

## Why Does This Matter?

### Business Impact

- **Direct Breach of Downstream Systems**: A leaked database credential or API key is not a foothold to be developed—it is immediate, authenticated access to the exact system the secret protects.
- **Financial Loss and Resource Abuse**: Leaked cloud or payment-provider keys are routinely used to spin up expensive resources (crypto mining) or move money, turning a code mistake into a bill or a fraud loss.
- **Permanent Exposure via Git History**: A secret committed once lives in the repository's history forever; deleting the line in a later commit does not remove it. Anyone who ever cloned or forked the repo keeps a copy.
- **Regulatory and Contractual Fallout**: Credentials guarding personal or cardholder data trigger GDPR, HIPAA, and PCI-DSS obligations, fines, and mandatory disclosure when they leak.
- **Expensive, Repeated Rotation**: When a static secret leaks, every system that ever received a copy must be found and rotated—a slow, error-prone scramble that automated rotation would have made routine.

### Technical Impact

- **Credential Disclosure**: Plaintext environment variables are visible in the console, returned by `GetFunctionConfiguration`, and included in many exception and diagnostic dumps.
- **Supply-Chain Exfiltration**: A single malicious or compromised dependency reads `process.env`/`os.environ` and ships every secret to an external endpoint, without touching your code.
- **Lateral Movement**: One over-shared secret reused across functions and services lets an attacker who obtains it pivot far beyond the function they first compromised.
- **Long-Lived Access**: Static, never-rotated keys mean a leak from months ago is very likely still valid today.
- **Log-Based Leakage**: Secrets echoed into CloudWatch (a dumped event, a printed config object) persist in log storage that is often broadly readable and long-retained.

## Technical Context

### Where Serverless Secrets Get Stored Insecurely

The weakness is best understood as a set of storage locations that feel like configuration but function as public-ish exposure. Each row below is a place a secret should *not* live in plaintext.

| Insecure Location | Why It Feels Convenient | Who Can Read It |
|-------------------|-------------------------|-----------------|
| Plaintext environment variables | Native to Lambda; one line in config | Console users, anyone with `lambda:GetFunctionConfiguration`, exception dumps, and all in-process code/dependencies |
| Hardcoded in source code | Works instantly with no setup | Everyone with repo read access—forever, via Git history |
| Committed `serverless.yml` / IaC | Keeps deploy config in one file | Everyone with repo access; often pushed to shared/public remotes |
| Deployment package / artifact | Bundling a `.env` "just works" | Anyone who can download the function's code or the build artifact |
| CloudWatch logs | A quick `print(event)` while debugging | Anyone with log read access; retained for the group's lifetime |
| One shared secret across functions | Copy-paste is faster than scoping | Every function—so a breach of any one exposes all |

### 1. Secrets in Plaintext Environment Variables

Lambda environment variables are the single most common place secrets end up. They are trivial to set, and the code reads them with one line—but they are stored and displayed in plaintext unless you explicitly encrypt them, and they are exposed through several channels at once.

```
# A function's environment, as returned by the platform API:
$ aws lambda get-function-configuration --function-name checkout
{
  "FunctionName": "checkout",
  "Environment": {
    "Variables": {
      "DB_PASSWORD": "S3cr3t-prod-pw",           # plaintext, right here
      "STRIPE_SECRET_KEY": "sk_live_51H...redacted",
      "JWT_SIGNING_KEY": "hunter2-super-secret"
    }
  }
}
# Anyone with lambda:GetFunctionConfiguration (or console access) reads them.
# The same values appear in the console UI and in many exception dumps.
```

**Risk**: Plaintext env vars are readable by console users, by any principal holding `lambda:GetFunctionConfiguration`, by code that dumps the environment on error, and—critically—by every dependency running in the function's process.

### 2. Hardcoded Secrets Committed to Git

```
// Committed to the repository on day one, forgotten forever after.
const STRIPE_KEY = "sk_live_51H...redacted";
const db = mysql.createConnection({
  host: "prod-db.internal",
  user: "app",
  password: "S3cr3t-prod-pw"   // now permanent in Git history
});
```

**Risk**: Even if a later commit removes the line, the secret remains in history and in every clone, fork, and backup. Public-repo scanners find such keys within minutes of a push.

### 3. Secrets Baked Into the Deployment Artifact

```
# The build zips everything in the directory, including a real .env:
checkout.zip
  |- index.js
  |- node_modules/...
  |- .env            # DB_PASSWORD=..., STRIPE_SECRET_KEY=sk_live_...
# Anyone who can download the function code / build artifact extracts the .env.
```

**Risk**: The artifact is not "inside" the function—it can be downloaded via the platform API or pulled from a build/CI store, handing over any credentials bundled with it.

### 4. Secrets in `serverless.yml` / Infrastructure as Code

```
# serverless.yml committed to the repo — plaintext secret as "config"
provider:
  name: aws
  environment:
    DB_PASSWORD: S3cr3t-prod-pw               # committed to version control
    STRIPE_SECRET_KEY: sk_live_51H...redacted  # visible to everyone with repo access
```

**Risk**: IaC is code, and code goes to version control. A secret here is both committed to history and injected into the function as a plaintext environment variable—two weaknesses in one line.

### 5. Over-Shared Secrets and No Rotation

Two amplifiers turn a single leak into a large breach. **Over-sharing** hands the same secret to every function regardless of need, so compromising any one function exposes credentials for systems it never touched. **No rotation** means the leaked value stays valid indefinitely—a key exposed a year ago is very likely still live today, and there is no automatic expiry to limit the damage window.

### 6. Secrets Echoed to Logs

```
// Debug line that quietly exfiltrates every secret into CloudWatch:
console.log("event:", JSON.stringify(event));   // tokens, keys in the event
console.log("config:", process.env);            // the entire secret environment
# These lines persist in log storage that is often broadly readable and
# retained far longer than anyone intends.
```

**Risk**: Logs are a durable, frequently over-permissioned store. A secret printed once may sit readable for months (ties to SAS-5).

## Real-World Impact

The examples below are described as **incident classes**—patterns repeatedly observed across the industry—rather than specific named breaches, because insecure secret storage is a category defined by how routinely and generically it happens.

### Case Class 1: Leaked Keys in Public and Shared Repositories

**Weakness**:
- Cloud access keys, database passwords, and third-party API keys are hardcoded in source or committed in configuration/IaC, then pushed to a public repository (or a private one that is later exposed).

**Impact**:
- Automated scanners continuously watch public code hosts and find newly committed credentials within minutes. Leaked cloud keys are widely observed being used to launch expensive compute (crypto mining) and to reach whatever data the key permits, before the owner even notices the commit.

**Root Cause**: Secrets treated as ordinary source or config, with no pre-commit scanning to stop them entering history. Cloud providers and code hosts now run secret-scanning and automatic key quarantine specifically because this pattern is so common.

### Case Class 2: Environment-Variable Secret Exposure

**Weakness**:
- Serverless functions store live credentials in plaintext environment variables. A separate weakness—an SSRF, a vulnerable dependency, an over-broad read permission, or a verbose error—then exposes that environment.

**Impact**:
- Repeated, well-documented incidents involve attackers reading a function's (or a workload's) environment and immediately obtaining the credentials it held, converting a low-severity information-disclosure bug into full access to databases and third-party services.

**Root Cause**: Secrets stored in plaintext where any environment-disclosure primitive becomes a credential-disclosure primitive, with no managed store or KMS encryption between the function and its secrets.

### Case Class 3: Compromised Dependency Reading the Environment

**Weakness**:
- A function bundles third-party packages that run in the same process as its plaintext secrets. One dependency (or a transitive one) is malicious or compromised.

**Impact**:
- Supply-chain incidents repeatedly show malicious packages that simply read `process.env`/`os.environ` and POST the contents to an external server. Because the secrets live in the environment, the attacker needs no vulnerability in your own code at all (ties to SAS-6 and SAS-10).

**Root Cause**: Long-lived secrets kept in-process and in-environment, reachable by any code the function runs, instead of fetched on demand and held only as briefly as needed.

## Prevalence and Statistics

Insecure secret storage is a durable member of the OWASP Serverless Top 10 (as SAS-7) and maps onto the broader OWASP Top 10 themes of cryptographic and identity failures. It is one of the most frequently found and most reliably exploited weaknesses, precisely because a leaked secret needs no exploit—it *is* the access.

Rather than cite precise figures (which vary by source and year), the defensible picture is:

- Secret leakage through source repositories is characterised across the industry as **extremely common and rapidly exploited**—public commits containing keys are found by automated scanners almost immediately.
- The most commonly observed patterns are **plaintext environment variables, hardcoded credentials in code, secrets in committed IaC, and secrets bundled into artifacts**.
- The impact is rated **high to critical**: exposure is often direct and total for the system the secret protects, and static, un-rotated secrets keep that exposure alive long after the leak.

> Note: exact counts of leaked credentials differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that secrets leak constantly, are found fast, and—without rotation—stay dangerous for a long time.

## Common Misunderstandings

### Myth 1: "Environment variables are secure—they're not in the code"

**Reality**: Environment variables are *configuration*, not *protection*. In Lambda they are stored and shown in plaintext by default, returned by `GetFunctionConfiguration`, and readable by every dependency in the process. Moving a secret from code to an env var changes where it leaks, not whether it leaks.

### Myth 2: "The repository is private, so committed secrets are fine"

**Reality**: Private repos are cloned to laptops, forked, backed up, and sometimes made public by accident. Access changes, contractors leave, and history is permanent. A secret in history is a secret you must rotate the moment repo access broadens.

### Myth 3: "I deleted the secret in a later commit, so it's gone"

**Reality**: Git keeps history. The old commit—and the secret in it—is still retrievable in every clone and on the host. The only safe response to a committed secret is to *rotate* it, not to delete the line.

### Myth 4: "We use a secrets manager, so we're done"

**Reality**: A managed store only helps if you actually fetch from it at runtime with a least-privilege role—not if you copy the secret out of it into a plaintext env var at deploy time. It also does nothing for secrets already sitting in Git history.

### Myth 5: "Rotation is overkill for internal keys"

**Reality**: Rotation is what limits the *blast radius of a leak you haven't noticed yet*. A static internal key that leaked months ago is still valid; an automatically rotated one would have expired. Rotation turns "permanent compromise" into "a short window."

### Myth 6: "Our function code is trusted, so in-process secrets are safe"

**Reality**: Your function runs far more than your code—every direct and transitive dependency executes in the same process with the same access to `process.env`. Trusting your own code says nothing about the hundreds of packages beside it.

## How SAS-7 Differs from Related Issues

| Aspect | Insecure Secrets Storage (SAS-7) | Insecure Deployment Config (SAS-3) | Over-Privileged Roles (SAS-4) |
|--------|-----------------------------------|-------------------------------------|--------------------------------|
| **Root cause** | Secrets stored where they can be read | Insecure deploy/runtime settings | Roles granted more access than needed |
| **What leaks** | The credential value itself | Configuration and exposure surface | Effective permissions of an identity |
| **Typical fix** | Managed store, KMS, rotation, no plaintext | Harden config, least exposure | Least-privilege, scoped policies |
| **Detection** | Secret scanning, config/artifact review | Config scan, IaC review | IAM analysis, access review |

## Key Takeaways

1. **Secrets are not configuration**—plaintext environment variables, code, IaC, and artifacts all expose them; treat every one of those as a leak.
2. **Git is forever**—a committed secret must be rotated, not just deleted, and scanning must stop it entering history in the first place.
3. **Fetch, don't embed**—pull secrets at runtime from a managed store with a least-privilege role, and cache them in memory rather than baking them in.
4. **Everything in the process can read the environment**—every dependency sees your env-var secrets, so keep them out of the environment where you can.
5. **Rotate and scope**—automatic rotation shrinks the damage window, and per-function scoping shrinks the blast radius.

## How to Identify if You're Vulnerable

- [ ] Are any live secrets stored in plaintext Lambda environment variables?
- [ ] Do any secrets appear in source code, in `serverless.yml`/IaC, or anywhere in Git history?
- [ ] Could a secret be bundled into the deployment package or build artifact (a committed `.env`, a config file)?
- [ ] Do functions fetch secrets at runtime from a managed store (Secrets Manager / SSM SecureString) with a least-privilege role?
- [ ] Are environment-variable secrets encrypted with KMS if you must use env vars at all?
- [ ] Is the same secret over-shared across many functions instead of scoped to the ones that need it?
- [ ] Are secrets rotated automatically, or are they static and effectively permanent?
- [ ] Could a compromised dependency read `process.env`/`os.environ` and find live secrets there?
- [ ] Do any log lines print events, config, or the environment that could contain secrets?
- [ ] Do you scan repositories and build artifacts for secrets (gitleaks/trufflehog) in CI and pre-commit?

If you answered "yes" to the exposure questions or "no"/"not sure" to the defence questions, you likely have live, exploitable secrets today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers locate and harvest serverless secrets
- **[Prevention](prevention.md)**: Store, fetch, scope, and rotate secrets the right way
- **[Examples](examples.md)**: Vulnerable vs. secure secret handling in Lambda and serverless.yml
