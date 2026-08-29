# SAS-7: Insecure Application Secrets Storage - Code Examples

Each pair below shows a **vulnerable** function (or configuration) and the **secure** version. The examples focus on what dominates real serverless findings: secrets in plaintext environment variables, hardcoded credentials, secrets in `serverless.yml`, and secrets echoed into logs—replaced by runtime fetches from Secrets Manager / SSM Parameter Store with KMS, caching, least-privilege roles, and rotation.

## 1. Lambda Handler — Node.js: Env-Var Secret vs. Secrets Manager

### Vulnerable
```
// The DB password lives in a plaintext environment variable. It is visible in
// the console, returned by GetFunctionConfiguration, dumped by exception
// handlers, and readable by every dependency in this process.
const mysql = require('mysql2/promise');

exports.handler = async (event) => {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD   // plaintext secret from the environment
  });
  const [rows] = await conn.query('SELECT * FROM orders WHERE id = ?',
                                  [event.pathParameters.id]);
  return { statusCode: 200, body: JSON.stringify(rows) };
};
```

### Secure
```
// The value is fetched at runtime from Secrets Manager with a least-privilege
// role, cached in memory across warm invocations, and never stored in an env var.
const mysql = require('mysql2/promise');
const { SecretsManagerClient, GetSecretValueCommand } =
  require('@aws-sdk/client-secrets-manager');
const sm = new SecretsManagerClient({});

let cachedSecret;                                  // survives warm invocations
async function getDbSecret() {
  if (cachedSecret) return cachedSecret;           // cache hit: no API call
  const out = await sm.send(new GetSecretValueCommand({
    SecretId: process.env.DB_SECRET_ID             // a NON-secret pointer only
  }));
  cachedSecret = JSON.parse(out.SecretString);
  return cachedSecret;
}

exports.handler = async (event) => {
  const { host, username, password } = await getDbSecret();
  const conn = await mysql.createConnection({ host, user: username, password });
  const [rows] = await conn.query('SELECT * FROM orders WHERE id = ?',
                                  [event.pathParameters.id]);
  return { statusCode: 200, body: JSON.stringify(rows) };
};
// The environment holds only DB_SECRET_ID (a name); the credential is never
// embedded, and rotation is transparent because each cold start re-fetches.
```

## 2. Lambda Handler — Python: Hardcoded Key vs. SSM SecureString + KMS

### Vulnerable
```
import json, urllib.request

# Hardcoded, committed to Git — permanent in history, found by scanners in minutes.
STRIPE_SECRET_KEY = "sk_live_51H...redacted"

def handler(event, context):
    req = urllib.request.Request(
        "https://api.stripe.com/v1/charges",
        headers={"Authorization": f"Bearer {STRIPE_SECRET_KEY}"},
        data=b"amount=1000&currency=usd",
    )
    resp = urllib.request.urlopen(req)
    return {"statusCode": 200, "body": resp.read().decode()}
```

### Secure
```
import json, os, urllib.request, boto3

ssm = boto3.client("ssm")
_cache = {}                                    # cache across warm invocations

def get_secret(name):
    if name in _cache:
        return _cache[name]                    # cache hit: no API call, no cost
    # WithDecryption uses KMS to decrypt the SecureString for an allowed caller.
    resp = ssm.get_parameter(Name=name, WithDecryption=True)
    _cache[name] = resp["Parameter"]["Value"]
    return _cache[name]

def handler(event, context):
    key = get_secret(os.environ["STRIPE_PARAM"])   # e.g. /prod/checkout/stripe_key
    req = urllib.request.Request(
        "https://api.stripe.com/v1/charges",
        headers={"Authorization": f"Bearer {key}"},
        data=b"amount=1000&currency=usd",
    )
    resp = urllib.request.urlopen(req)
    return {"statusCode": 200, "body": resp.read().decode()}
# The key is a KMS-encrypted SSM SecureString, fetched at runtime and cached.
# Nothing sensitive is in the code, the repo, or the environment.
```

## 3. serverless.yml — Inline Secret vs. Reference by Name

### Vulnerable
```
# Secrets pasted straight into IaC: committed to version control AND injected
# into the function as plaintext environment variables. Two weaknesses, one file.
service: checkout
provider:
  name: aws
  runtime: nodejs20.x
  environment:
    DB_PASSWORD: S3cr3t-prod-pw                 # committed + plaintext env var
    STRIPE_SECRET_KEY: sk_live_51H...redacted    # committed + plaintext env var
functions:
  checkout:
    handler: index.handler
```

### Secure
```
# Only NON-secret pointers are in the file; the function fetches values at
# runtime. The role is scoped to exactly the secrets this function needs.
service: checkout
provider:
  name: aws
  runtime: nodejs20.x
  environment:
    DB_SECRET_ID: prod/checkout/db              # a name, not a value
    STRIPE_PARAM: /prod/checkout/stripe_key      # a name, not a value
  iam:
    role:
      statements:
        - Effect: Allow
          Action: secretsmanager:GetSecretValue
          Resource: arn:aws:secretsmanager:*:*:secret:prod/checkout/db-*
        - Effect: Allow
          Action: ssm:GetParameter
          Resource: arn:aws:ssm:*:*:parameter/prod/checkout/stripe_key
        - Effect: Allow
          Action: kms:Decrypt
          Resource: arn:aws:kms:*:*:key/abc-123   # the CMK protecting the secrets
functions:
  checkout:
    handler: index.handler
package:
  patterns:
    - '!.env'                                    # never bundle local secret files
    - '!**/*.pem'
```

## 4. Environment Variables You Cannot Avoid: Encrypt With KMS

### Vulnerable
```
# The env var is stored and displayed in plaintext. Anyone with
# lambda:GetFunctionConfiguration or console access reads it directly.
provider:
  environment:
    THIRD_PARTY_TOKEN: tok_live_abc123           # plaintext at rest in the config
```

### Secure
```
# If an integration truly must read from the environment, encrypt env vars at
# rest with a customer-managed KMS key. Prefer a managed store — this is the
# fallback, not the goal.
provider:
  kmsKeyArn: arn:aws:kms:us-east-1:123456789012:key/abc-123  # encrypts env vars

# The stored value is ciphertext; the function decrypts at cold start:
# (Node.js) const { KMSClient, DecryptCommand } = require('@aws-sdk/client-kms');
#   const plaintext = (await kms.send(new DecryptCommand({
#     CiphertextBlob: Buffer.from(process.env.THIRD_PARTY_TOKEN, 'base64')
#   }))).Plaintext.toString();
# Note: the decrypted value still lives in memory, readable by in-process deps.
```

## 5. Secrets Baked Into the Artifact vs. a Clean Package

### Vulnerable
```
# A real .env is committed and zipped into the deployment package. Anyone who
# downloads the function's code (GetFunction) or the CI artifact extracts it.
checkout.zip
  |- index.js
  |- node_modules/...
  |- .env            # DB_PASSWORD=S3cr3t-prod-pw, STRIPE_SECRET_KEY=sk_live_...
# .env is tracked in Git and NOT excluded from packaging.
```

### Secure
```
# .env is git-ignored, excluded from the package, and holds no production values.
# The artifact contains code only; secrets come from the managed store at runtime.

# .gitignore
.env
*.pem
*.key

# serverless.yml (packaging)
package:
  patterns:
    - '!.env'
    - '!**/*.pem'
    - '!**/*.key'

# Verify the built artifact carries no secrets before it ships:
$ trufflehog filesystem ./.serverless --only-verified
$ unzip -l .serverless/checkout.zip | grep -E '\.env|\.pem|\.key' || echo "clean"
```

## 6. Rotation and No-Secret Auth

### Vulnerable
```
# A static DB password, set once and never changed. A leak from months ago is
# still valid today, and rotating it means editing config and redeploying by hand.
DB_PASSWORD = "S3cr3t-prod-pw"   # same value since the service launched
```

### Secure
```
# Managed rotation: the secret changes on a schedule, and the function always
# fetches the CURRENT value at runtime, so rotation needs no redeploy.
$ aws secretsmanager rotate-secret \
    --secret-id prod/checkout/db \
    --rotation-lambda-arn arn:aws:lambda:...:function:SecretsManagerRDSRotation \
    --rotation-rules '{"AutomaticallyAfterDays": 30}'

# Better still, remove the static secret entirely where possible — use IAM
# database authentication so the function authenticates with a short-lived
# token minted from its execution role (no stored password at all):
#   token = rds_client.generate_db_auth_token(host, 5432, db_user)
```

## 7. Redacting Secrets in Logs

### Vulnerable
```
// Debug lines that quietly write every secret into CloudWatch, where anyone with
// log read access reads them back for the group's whole retention.
console.log("event:", JSON.stringify(event));   // tokens/keys inside the event
console.log("config:", process.env);            // the entire secret environment
```

### Secure
```
// Log identifiers and outcomes, never values. Redact known-sensitive fields,
// and disable verbose/framework debug output in production.
const REDACT = new Set(['password','db_password','stripe_secret_key','token','authorization']);
function safe(obj) {
  return Object.fromEntries(Object.entries(obj)
    .map(([k, v]) => [k, REDACT.has(k.toLowerCase()) ? '***' : v]));
}
console.log('request', safe({ orderId: event.pathParameters?.id, outcome: 'ALLOW' }));
// Never console.log(process.env) or the raw event; scrub before emitting.
```

## What Changed, and Why

| Gap | Vulnerable | Secure |
|-----|------------|--------|
| Where the secret lives | Plaintext env var / hardcoded / in IaC | Managed store (Secrets Manager / SSM SecureString), KMS-encrypted |
| How code gets it | Embedded at deploy time | Fetched at runtime, cached in memory |
| Access scope | One shared secret, broad reads | Least-privilege role, per-function ARNs |
| Artifact / Git | `.env` bundled; secret in history | Git-ignored, excluded from package, scanned |
| Lifetime | Static, never rotated | Automatic rotation; IAM/short-lived where possible |
| Logs | Event/env dumped verbatim | Redacted; values never printed |

## Next Steps

- **[Prevention](prevention.md)**: The full serverless secrets strategy
- **[Attack Vectors](attack-vectors.md)**: The exposure these controls shut down
- **[Overview](overview.md)**: Why serverless secrets leak so easily
