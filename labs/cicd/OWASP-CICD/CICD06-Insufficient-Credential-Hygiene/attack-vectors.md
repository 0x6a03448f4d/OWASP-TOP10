# CICD-SEC-6: Insufficient Credential Hygiene - Attack Vectors

## Table of Contents
- [Understanding Credential-Hygiene Attack Vectors](#understanding-credential-hygiene-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Credential Leaks](#chaining-credential-leaks)

## Understanding Credential-Hygiene Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Exploiting insufficient credential hygiene almost never involves breaking anything. The attacker's core move is **harvest and reuse**: locate a credential that a careless pipeline exposed—in Git history, a build log, an environment dump, or an artifact—and then present it to whatever system trusts it. Because the credential is genuine, the target treats the attacker as a legitimate client. There is no payload to craft and often no anomaly to detect.

The attacker's goal in this category is one of:

- Find an exposed secret cheaply and at scale (automated scanning of public and internal sources).
- Reuse a long-lived, broadly scoped credential against cloud, registry, database, or prod.
- Turn one leaked token into persistence and lateral movement across environments and pipelines.

### Core Attack Flow

```
1. Harvest
   |
   Scan Git history, public repos, build logs, artifacts, env dumps
2. Validate
   |
   Test the credential (whoami / list / describe) to learn its scope
3. Reuse
   |
   Authenticate to cloud / registry / DB / prod as a legitimate client
4. Escalate / Persist
   |
   Pivot via over-shared tokens, mint new keys, exfiltrate or tamper
```

## Common Attack Patterns

### 1. Harvesting Secrets from Git History

Removing a secret from the latest commit leaves it fully recoverable in history. Attackers clone and mine the entire history, not just the working tree.

```bash
# Recover a secret that was "deleted" in a later commit:
git clone https://target/repo.git && cd repo
git log --all --oneline
git grep -I -i "aws_secret\|api_key\|token" $(git rev-list --all)
# Or with a scanner across full history:
trufflehog git file://./repo --only-verified
```

**Payoff**: any credential ever committed, even if it looks "gone" in the current tree. This is why deletion without rotation is not remediation.

### 2. Scraping Hardcoded Secrets from Code and Pipeline Files

Secrets in application config, pipeline YAML, and Dockerfiles are read directly—no history digging required.

```
# Public and internal code search finds patterns instantly:
filename:.env  DB_PASSWORD
path:.github/workflows  AWS_SECRET_ACCESS_KEY
extension:tf  access_key

# Automated bots watch public push events and grab keys within minutes.
```

**Payoff**: immediate access with a valid key; on public platforms the exposure-to-abuse window is often minutes.

### 3. Extracting Secrets from Build Logs

Debug tracing and explicit prints defeat log masking, and logs are widely readable and long-retained.

```bash
# In the pipeline (INSECURE) — masking is bypassed:
+ export DEPLOY_TOKEN=ghp_ab12...            # from set -x tracing
DEBUG: connecting with token=ghp_ab12...     # from an echo

# Attacker with log read access simply searches:
grep -Eo 'gh[pousr]_[A-Za-z0-9]{20,}' pipeline-*.log
```

**Payoff**: secrets readable by everyone with log access—often a far larger group than those trusted with the secret—and persisted in log storage.

### 4. Pulling Secrets from Environment Dumps

Any step that can run a command can print the whole environment, and job-wide secrets are all present in it.

```bash
# A malicious or compromised build step:
env | base64            # exfiltrate all env vars past naive masking
printenv > /tmp/leak    # or write them to an uploaded artifact

# Everything injected for the job is visible, not just what this step needs.
```

**Payoff**: all job-scoped secrets at once—this is why over-broad, job-wide secret injection is dangerous.

### 5. Recovering Secrets from Artifacts and Container Images

Credentials baked in at build time travel inside the artifact and are trivially extracted later.

```bash
# Image layers reveal build-time ARGs and copied files:
docker history --no-trunc myapp:latest
docker save myapp:latest -o img.tar && tar xf img.tar   # inspect layers
# Build artifacts often bundle config:
tar tzf release.tgz | grep -i 'env\|secret\|credential'
```

**Payoff**: any secret embedded during the build—pulled from a registry or downloaded artifact with no access to the pipeline at all.

### 6. Reusing Long-Lived Static Credentials

Once a static key is in hand, the attacker validates its scope and uses it directly. Long-lived keys with no expiry give durable access.

```bash
# Validate and enumerate scope:
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name ci-deployer

# Reuse against production — the key is genuine, so it "just works":
aws s3 sync s3://prod-data ./exfil
aws ec2 run-instances --count 50 ...        # cryptomining on the victim's bill
```

**Payoff**: full access at the credential's (often broad) scope, persisting until someone rotates the key.

### 7. Abusing Over-Shared "God" Tokens

A single token shared across many pipelines and repos lets one leak reach far beyond its origin.

```bash
# One registry/cloud token used everywhere:
#   leaked from a single low-value pipeline
#   but valid for prod registry pushes and multiple accounts
docker login registry.example.com -u ci -p $LEAKED_TOKEN
docker push registry.example.com/prod/app:backdoored
```

**Payoff**: lateral movement across environments and, via registry/signing access, potential supply-chain poisoning of downstream consumers.

### 8. Minting New Credentials for Persistence

If a harvested credential can create other credentials, the attacker establishes access that survives rotation of the original.

```bash
# With an over-privileged key, create a durable backdoor identity:
aws iam create-access-key --user-name attacker-added
# Now rotating the leaked key does not evict the attacker.
```

**Payoff**: persistence independent of the original leak—why over-privileged CI identities are so dangerous.

### 9. Exploiting Missing Leak Detection

Where there is no secret scanning in pre-commit or CI, leaks are discovered by whoever scans first—usually the attacker.

```
# No gitleaks/trufflehog gate on commits or PRs:
#   secret merges to main, is mirrored, cached, and forked
#   defenders learn of it only when abuse is already underway
```

**Payoff**: a long, silent exposure window in which the credential is live and unmonitored.

## Chaining Credential Leaks

Individually small hygiene failures combine into full compromise:

```
Hardcoded key removed from HEAD    -> still recoverable from Git history
        +
Key is long-lived and broadly scoped -> validates as AdministratorAccess
        +
No rotation and no scanning         -> access persists, undetected
        =  full cloud-account takeover, no exploit required
```

Another common chain:

```
set -x prints a registry token to the build log
        -> log is world-readable inside the org, token harvested
        -> token is over-shared, valid for the prod registry
        -> attacker pushes a poisoned image every downstream consumer trusts
```

## Key Takeaways

1. **The attack is harvest-and-reuse, not exploitation**—a valid credential needs no payload, so there is little to detect.
2. **History, logs, env, and artifacts are all harvest sources**—a secret leaks from far more places than the file it was typed into.
3. **Long-lived and broadly scoped keys turn a small leak into a big breach**—and enable persistence via newly minted credentials.
4. **Over-shared tokens spread the blast radius**—one leak reaches every pipeline that trusts the token.
5. **No scanning means the attacker finds it first**—silent exposure windows are where these breaches happen.

## Next Steps

- **[Prevention Guide](prevention.md)**: Shrink the value and lifetime of every secret
- **[Code Examples](examples.md)**: See insecure vs. secure secret handling side by side
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
