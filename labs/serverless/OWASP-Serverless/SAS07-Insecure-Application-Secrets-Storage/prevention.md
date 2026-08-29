# SAS-7: Insecure Application Secrets Storage - Prevention

## Prevention Strategy Overview

Preventing this weakness is a single principle applied everywhere: **secrets are fetched, never embedded**. Keep the value in a managed, encrypted store; retrieve it at runtime with a least-privilege role; and make sure it never appears in code, config, artifacts, history, or logs.

1. Store secrets in a managed secret store (Secrets Manager / SSM Parameter Store SecureString), encrypted with KMS.
2. Fetch at runtime with a least-privilege role, and cache in memory to limit calls and cost.
3. Keep secrets out of code, environment variables, IaC, and Git entirely.
4. If you must use environment variables, encrypt them with KMS—and prefer not to.
5. Rotate secrets automatically, scope them per function, scan repos and artifacts, and redact logs.

### Core Principles

- **Fetch, don't embed**: a secret retrieved on demand is not sitting in a place an attacker can read at rest.
- **Least privilege to the secret**: each function's role can read only the specific secrets it needs, nothing more.
- **Assume the environment is public**: treat `process.env`/`os.environ` as readable by every dependency and by the platform API.
- **Short-lived beats long-lived**: rotate secrets and prefer IAM roles / temporary credentials over static keys wherever possible.

## 1. Store Secrets in a Managed, Encrypted Store

Put every secret in a purpose-built store that encrypts at rest with KMS and gates access through IAM. The two native AWS options are **Secrets Manager** (built-in rotation, JSON secrets) and **SSM Parameter Store SecureString** (cheaper, KMS-encrypted parameters).

```
# Create the secret out-of-band (never in the repo), KMS-encrypted:
$ aws secretsmanager create-secret \
    --name prod/checkout/db \
    --secret-string '{"username":"app","password":"S3cr3t-prod-pw"}' \
    --kms-key-id alias/checkout-secrets

# Or as an SSM SecureString parameter (KMS-encrypted):
$ aws ssm put-parameter \
    --name /prod/checkout/stripe_key \
    --type SecureString \
    --key-id alias/checkout-secrets \
    --value 'sk_live_51H...redacted'
```

Both stores keep the value encrypted at rest and hand out plaintext only to callers whose IAM policy explicitly allows it—so the secret is never in your code, config, or history.

## 2. Fetch at Runtime With a Least-Privilege Role (and Cache)

Retrieve the secret when the function needs it, using the function's execution role, and cache it in memory across warm invocations so you are not paying for a lookup on every request.

```
// Node.js (Lambda): fetch once, cache for the container's lifetime
const { SecretsManagerClient, GetSecretValueCommand } =
  require('@aws-sdk/client-secrets-manager');
const sm = new SecretsManagerClient({});

let cached;                                   // survives warm invocations
async function getDbSecret() {
  if (cached) return cached;                  // cache hit: no API call, no cost
  const out = await sm.send(new GetSecretValueCommand({
    SecretId: 'prod/checkout/db'
  }));
  cached = JSON.parse(out.SecretString);
  return cached;
}

exports.handler = async (event) => {
  const { username, password } = await getDbSecret();  // fetched, not embedded
  // ...use the credential, never log it...
};
```

Scope the execution role to exactly the one secret:

```
# IAM policy attached to the function's role — least privilege to ONE secret
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/checkout/db-*"
}
# Plus kms:Decrypt on the specific key, if the secret uses a customer-managed key.
```

> For lower latency and cost, use the AWS Parameters and Secrets Lambda Extension (or Powertools' `getSecret` with a TTL) instead of hand-rolled caching—it caches fetched secrets in the execution environment for you.

## 3. Keep Secrets Out of Code, Env Vars, IaC, and Git

The most reliable defence is that the value simply is not there to leak. Reference secrets by *name/ARN* in configuration—never by value.

```
# serverless.yml — reference the secret, never inline it.
provider:
  name: aws
  environment:
    # Store only the NON-secret pointer; the function fetches the value at runtime.
    DB_SECRET_ID: prod/checkout/db
    STRIPE_PARAM: /prod/checkout/stripe_key
  iam:
    role:
      statements:
        - Effect: Allow
          Action: secretsmanager:GetSecretValue
          Resource: arn:aws:secretsmanager:*:*:secret:prod/checkout/db-*
        - Effect: Allow
          Action: ssm:GetParameter
          Resource: arn:aws:ssm:*:*:parameter/prod/checkout/stripe_key
```

Add a `.gitignore` for `.env` and local secret files, and never bundle them into the deployment package—use the framework's package/exclude rules so the artifact contains code only.

## 4. If You Must Use Environment Variables, Encrypt Them With KMS

Sometimes an integration only reads a value from the environment. If you truly cannot avoid an env var, encrypt it with a customer-managed KMS key and decrypt in-process, so the plaintext is never stored in the function configuration.

```
# serverless.yml — encrypt env-var values at rest with a CMK
provider:
  kmsKeyArn: arn:aws:kms:us-east-1:123456789012:key/abc-123   # encrypts env vars
# The stored value is ciphertext; the function decrypts it at cold start with
# kms:Decrypt. Prefer a managed store over this — it is the fallback, not the goal.
```

This is strictly a mitigation: it protects the value at rest in the config, but the decrypted secret still lives in `process.env` at runtime, readable by in-process dependencies. A managed store fetched on demand is still preferable.

## 5. Rotate Secrets Automatically

Rotation is what limits the damage of a leak you have not noticed. Turn on managed rotation so credentials expire on a schedule and a stolen value becomes useless quickly.

```
# Enable Secrets Manager rotation (managed rotation Lambda handles the change):
$ aws secretsmanager rotate-secret \
    --secret-id prod/checkout/db \
    --rotation-lambda-arn arn:aws:lambda:...:function:SecretsManagerRDSRotation \
    --rotation-rules '{"AutomaticallyAfterDays": 30}'
# The function always fetches the CURRENT value at runtime, so rotation is
# transparent to the code — no redeploy, no manual key swap.
```

## 6. Scope Secrets Per Function

Do not hand one shared secret to every function. Give each function its own least-privilege access to only the secrets it needs, so compromising one function cannot expose credentials for systems it never touched.

- One secret (or namespaced path) per purpose: `/prod/checkout/db`, `/prod/reports/db`—not a single shared `DB_PASSWORD`.
- Grant each function's role `GetSecretValue`/`GetParameter` on *only* its own ARNs.
- Use distinct downstream credentials per function where practical, so a leaked one is scoped and independently rotatable (ties to SAS-4).

## 7. Scan Repositories and Artifacts for Secrets

Catch secrets before they are committed and before they ship. Run a secret scanner as a pre-commit hook *and* in CI, over both the working tree and full history, and over the built artifact.

```
# Pre-commit and CI scanning (gitleaks / trufflehog):
$ gitleaks detect --source . --redact          # scan working tree + history
$ trufflehog filesystem ./dist --only-verified # scan the build output/artifact

# Fail the pipeline on any finding, and scan history to catch what already landed:
$ gitleaks detect --log-opts="--all" --exit-code 1
```

```
# .pre-commit-config.yaml — stop secrets before they enter history
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

Also enable your code host's native push protection / secret scanning as a second net. If a scan finds a live secret, **rotate it**—removing the line is not enough.

## 8. Redact Secrets From Logs and Errors

Never print the event, the environment, or config objects. Log identifiers and outcomes, not values, and scrub known-sensitive fields before emitting (ties to SAS-5).

```
// Redact before logging — never console.log(process.env) or the raw event.
const REDACT = new Set(['password','db_password','stripe_secret_key','token','authorization']);
function safe(obj) {
  return Object.fromEntries(Object.entries(obj)
    .map(([k, v]) => [k, REDACT.has(k.toLowerCase()) ? '***' : v]));
}
console.log('request', safe({ orderId: id, user: userId }));  // no secrets
// Disable verbose/framework debug output in production so errors don't dump env.
```

## 9. Prefer Short-Lived Credentials Over Static Keys

Where a secret is really just an identity, replace it with an IAM role. Functions already run with an execution role—use it (and cross-account `AssumeRole`, or IAM database authentication) so there is no static key to store, leak, or rotate at all.

- Talk to AWS services via the execution role, not stored access keys.
- Use IAM authentication for RDS/Aurora instead of a static DB password where supported.
- For third parties, prefer short-lived, scoped tokens over long-lived API keys when the provider offers them.

## Serverless Secrets Checklist

| Control | What It Buys You |
|---------|------------------|
| Managed store (Secrets Manager / SSM SecureString) | Secrets encrypted at rest, gated by IAM, out of code and history |
| Runtime fetch + in-memory cache | No embedded value; low latency and cost |
| KMS encryption | Ciphertext at rest; decrypt only with the right key |
| Least-privilege, per-function access | Small blast radius when any one function is compromised |
| Automatic rotation | A leaked secret expires quickly and transparently |
| Secret scanning (gitleaks/trufflehog + push protection) | Stops secrets entering repos and artifacts |
| Log/error redaction | Secrets never persist in CloudWatch or error trackers |
| Short-lived creds / IAM roles | Fewer static secrets to store, leak, or rotate |

## Key Takeaways

1. **Fetch, don't embed** — store secrets in a managed, KMS-encrypted store and retrieve them at runtime with a least-privilege role.
2. **Cache the fetch** — hold the value in memory across warm invocations to keep latency and cost down.
3. **Keep secrets out of code, env vars, IaC, and Git** — reference by name/ARN, and if you must use env vars, encrypt them with KMS.
4. **Rotate and scope** — automatic rotation shrinks the window of a leak; per-function access shrinks its blast radius.
5. **Scan and redact** — block secrets from repos and artifacts, keep them out of logs, and rotate anything that ever leaked.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure secret handling in Lambda and serverless.yml
- **[Attack Vectors](attack-vectors.md)**: Understand exactly what these controls shut down
- **[Overview](overview.md)**: Why serverless secrets leak so easily
