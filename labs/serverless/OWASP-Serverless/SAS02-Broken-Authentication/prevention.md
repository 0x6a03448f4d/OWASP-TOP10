# SAS-2: Broken Authentication - Prevention

## Prevention Strategy Overview

Preventing broken authentication in serverless is less about one clever control and more about **making "authenticated at every entry point" the only way a function ever runs**:

1. Enumerate every function and every trigger, and treat each as directly reachable.
2. Enforce authentication at each entry point—not only the API Gateway.
3. Centralise identity in one provider and reuse a consistent authorizer.
4. Validate tokens completely: signature, expiry, audience, issuer.
5. Sign service-to-service calls (IAM/SigV4) and scope every role to least privilege.

### Core Principles

- **Authenticate every door**: the gateway is one entry point of many; URLs, event sources, and direct invokes each need their own enforced authentication.
- **Central identity, not per-function improvisation**: one provider (e.g. Cognito) and a shared authorizer are far harder to get wrong than ad-hoc checks.
- **Assume direct reachability**: design each function as if an attacker can call it directly, then authenticate accordingly.
- **Least privilege as a backstop**: if an unauthenticated call ever slips through, a tight execution role limits what it can do.

## 1. Enforce Authentication at Every Entry Point

Start by inventorying triggers, then require authentication on each. Never leave a Function URL open.

```yaml
# serverless.yml — require IAM auth on the Function URL (never AuthType NONE)
functions:
  adminReport:
    handler: handler.adminReport
    url:
      authorizer: aws_iam        # callers must sign requests with SigV4

# API Gateway routes: attach the authorizer to EVERY protected route
provider:
  httpApi:
    authorizers:
      cognitoAuth:
        type: jwt
        identitySource: $request.header.Authorization
        issuerUrl: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXX
        audience:
          - 6f0abc123clientid
functions:
  getProfile:
    handler: handler.getProfile
    events:
      - httpApi:
          path: /profile
          method: get
          authorizer:
            name: cognitoAuth      # no route ships without an authorizer
```

Audit for the gaps: any function with a Function URL, and any route without an authorizer, is an unauthenticated entry point until proven otherwise.

## 2. Use a Central Identity Provider and API Gateway Authorizers

Delegate user authentication to a managed identity provider rather than hand-rolling it per function.

```yaml
# Cognito JWT authorizer (as above) validates the token BEFORE the function runs.
# For custom needs, a single shared Lambda authorizer — reused by every route —
# keeps verification logic in one reviewed place instead of copied into handlers.

functions:
  authorizer:
    handler: auth.verify          # one authorizer, reused everywhere
  orders:
    handler: handler.orders
    events:
      - httpApi:
          path: /orders
          method: post
          authorizer:
            name: sharedLambdaAuth
```

A consistent authorizer means a fix or a policy change happens once and applies to the whole fleet, instead of drifting across dozens of handlers.

## 3. Validate Tokens Correctly

Verify the signature against the provider's keys, and check expiry, audience, and issuer—every time.

```javascript
// Node.js Lambda authorizer — full JWT verification with the provider JWKS
const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS = createRemoteJWKSet(new URL(process.env.JWKS_URI));

exports.verify = async (event) => {
  const token = (event.headers.authorization || '').replace(/^Bearer /, '');
  const { payload } = await jwtVerify(token, JWKS, {
    issuer:   process.env.EXPECTED_ISSUER,     // iss
    audience: process.env.EXPECTED_AUDIENCE,   // aud
    // jwtVerify also enforces the signature and exp automatically
  });
  return { isAuthorized: true, context: { sub: payload.sub, scope: payload.scope } };
};
```

Reject `alg: none`, never trust an unverified claim, and keep token lifetimes short so a leaked token expires quickly.

## 4. Do Not Trust Event Triggers as "Internal"

Treat every event payload as untrusted input. Verify the source and validate the content before acting on it.

```python
# Python Lambda — validate the S3 event's context before privileged work
import os

TRUSTED_BUCKET = os.environ['TRUSTED_BUCKET']

def handler(event, context):
    rec = event['Records'][0]
    bucket = rec['s3']['bucket']['name']
    if bucket != TRUSTED_BUCKET:              # confirm the expected source
        raise Exception('event from unexpected bucket')
    key = rec['s3']['object']['key']
    validate_object(bucket, key)              # scan/validate BEFORE processing
    process_import(bucket, key)
```

Where the actor matters, carry an authenticated identity in the payload (a signed token or message attribute) and verify it—do not infer trust from the trigger type.

## 5. Secure Service-to-Service Authentication

Internal invokes must be authenticated too. Use IAM/SigV4 and least-privilege roles instead of shared static secrets.

```yaml
# serverless.yml — the caller may invoke ONLY the one function it needs
functions:
  caller:
    handler: caller.handler
    iamRoleStatements:
      - Effect: Allow
        Action: lambda:InvokeFunction
        Resource: arn:aws:lambda:us-east-1:1234:function:internalSync

# Function URLs / HTTP calls between services: sign with SigV4 so the callee
# can verify the calling principal via IAM, not a guessable header value.
```

Avoid a single shared API key across services; if it leaks, every service is exposed and there is no per-caller identity to revoke.

## 6. Least Privilege for Every Function

Scope each function's execution role so that even an unauthenticated invocation can do little.

```yaml
# Bad: one broad role reused everywhere
- Effect: Allow
  Action: dynamodb:*
  Resource: "*"

# Good: per-function, per-resource, least privilege
- Effect: Allow
  Action: [ dynamodb:GetItem ]
  Resource: arn:aws:dynamodb:us-east-1:1234:table/Profiles
```

Least privilege does not replace authentication—it caps the blast radius when authentication fails.

## 7. No Long-Lived or Static Credentials

- Issue short-lived tokens and refresh them; set and enforce an `exp` claim.
- Rotate any keys automatically; never bake secrets into code or images.
- Store secrets in a manager (AWS Secrets Manager, SSM Parameter Store, KMS) and fetch at runtime.

```bash
# Reject secrets committed to the repo at commit time
gitleaks detect --source . --redact
```

## 8. Do Not Rely on Obscurity of URLs or ARNs

Assume every Function URL and ARN is public knowledge. Keep them out of client bundles and logs where practical, but always back them with real authentication—obscurity is never the control.

## 9. Detect Unauthenticated Entry Points Automatically

Add gates to CI so an open door fails the build.

```bash
# In CI: scan IaC for Function URLs without auth and routes without authorizers
checkov -d ./  --check CKV_AWS_258        # Lambda Function URL auth type
cfn-lint template.yaml

# Simple guard: fail if any Function URL is AuthType NONE
grep -R "authorizer:\s*none" serverless.yml && exit 1 || true
```

Run these on every pull request, and periodically enumerate deployed functions/URLs to catch drift.

## 10. Monitoring and Detection

Watch for the signatures of authentication bypass and abuse.

```
# Alert on invocations that skipped the gateway or failed auth
- Function URL invocations with no associated authenticated principal
- Spikes of 401/403 at authorizers (credential stuffing / token forgery attempts)
- Direct lambda:Invoke calls from unexpected principals (CloudTrail)
- Tokens presented long after issue time (possible replay of stale tokens)
```

Feed CloudTrail and authorizer logs into alerting so an unexpected direct invoke or a burst of auth failures is surfaced quickly.

## Framework-Specific Hardening

### AWS Lambda + API Gateway (HTTP API)

```
# Every route carries an authorizer; no route defaults to open.
# Function URLs use aws_iam. Cognito (or an OIDC provider) issues short-lived
# JWTs. A single JWT/Lambda authorizer verifies signature + exp + aud + iss.
```

### AWS Lambda (Python handler backstop)

```python
def handler(event, context):
    # Even behind an authorizer, re-derive identity from the verified context —
    # never from a client-supplied header the function trusts blindly.
    claims = event['requestContext']['authorizer']['jwt']['claims']
    user = claims['sub']            # provided by the gateway authorizer
    # proceed with an authenticated identity, scoped by least-privilege role
```

## Key Takeaways

1. **Authenticate every entry point** — gateway, Function URLs, event sources, and direct invokes all need enforcement.
2. **Centralise identity** — one provider plus a reused authorizer beats per-function checks that drift.
3. **Verify tokens fully** — signature, expiry, audience, and issuer, every time; reject `alg: none`.
4. **Never trust a trigger as identity** — validate event sources and payloads; sign service-to-service calls.
5. **Least privilege and short lifetimes** — cap the blast radius and make leaked credentials expire fast.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure auth in Lambda and API Gateway
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Serverless Learning Path](/learn/serverless)**: Continue with the rest of the Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
