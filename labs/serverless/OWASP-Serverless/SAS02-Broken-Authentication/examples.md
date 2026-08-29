# SAS-2: Broken Authentication - Code Examples

Each pair below shows a **vulnerable** configuration and the **secure** version for the same scenario. The examples focus on the failures that dominate real serverless findings: entry points that bypass the gateway, event triggers trusted as "internal," decode-only token checks, and unauthenticated service-to-service calls.

## 1. Lambda Function URL (serverless.yml)

### Vulnerable
```yaml
functions:
  adminReport:
    handler: handler.adminReport
    url:
      authorizer: none          # AuthType NONE — public endpoint, bypasses API Gateway
    # A random-looking lambda-url host is the ONLY thing standing between
    # the internet and privileged reporting logic.
```

### Secure
```yaml
functions:
  adminReport:
    handler: handler.adminReport
    url:
      authorizer: aws_iam       # callers must sign requests (SigV4); IAM verifies principal
    # For end-user access, prefer routing through API Gateway with a JWT
    # authorizer instead of exposing a Function URL at all.
```

## 2. API Gateway Authorizer Coverage (serverless.yml)

### Vulnerable
```yaml
provider:
  httpApi:
    authorizers:
      cognitoAuth:
        type: jwt
        identitySource: $request.header.Authorization
        issuerUrl: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXX
        audience: [ 6f0abc123clientid ]

functions:
  getProfile:
    handler: handler.getProfile
    events:
      - httpApi: { path: /profile, method: get, authorizer: { name: cognitoAuth } }
  exportData:
    handler: handler.exportData
    events:
      - httpApi: { path: /export, method: get }   # NO authorizer — silently public
```

### Secure
```yaml
functions:
  getProfile:
    handler: handler.getProfile
    events:
      - httpApi: { path: /profile, method: get, authorizer: { name: cognitoAuth } }
  exportData:
    handler: handler.exportData
    events:
      - httpApi:
          path: /export
          method: get
          authorizer: { name: cognitoAuth }        # every route carries an authorizer
```

## 3. JWT Validation in a Lambda Authorizer (Node.js)

### Vulnerable
```javascript
// Decodes the token but never verifies it — claims are attacker-controlled
exports.verify = async (event) => {
  const token = (event.headers.authorization || '').replace(/^Bearer /, '');
  const body = token.split('.')[1];
  const claims = JSON.parse(Buffer.from(body, 'base64').toString());  // decode only
  if (claims.role === 'admin') {
    return { isAuthorized: true, context: { sub: claims.sub } };      // forged easily
  }
  return { isAuthorized: false };
};
```

### Secure
```javascript
// Verifies signature + exp + aud + iss against the provider's JWKS
const { createRemoteJWKSet, jwtVerify } = require('jose');
const JWKS = createRemoteJWKSet(new URL(process.env.JWKS_URI));

exports.verify = async (event) => {
  const token = (event.headers.authorization || '').replace(/^Bearer /, '');
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer:   process.env.EXPECTED_ISSUER,     // iss
      audience: process.env.EXPECTED_AUDIENCE,   // aud
      // signature and exp are enforced by jwtVerify; alg 'none' is rejected
    });
    return { isAuthorized: true, context: { sub: payload.sub, scope: payload.scope } };
  } catch {
    return { isAuthorized: false };              // any failure denies access
  }
};
```

## 4. Event-Triggered Function (Python)

### Vulnerable
```python
# Trusts the S3 event because it "came from AWS" — the uploader may be untrusted
def handler(event, context):
    rec = event['Records'][0]
    key = rec['s3']['object']['key']
    process_import(key)          # privileged: parses file, writes to prod DB
    grant_entitlements(key)      # acts with no authenticated actor behind it
```

### Secure
```python
import os
TRUSTED_BUCKET = os.environ['TRUSTED_BUCKET']

def handler(event, context):
    rec = event['Records'][0]
    bucket = rec['s3']['bucket']['name']
    if bucket != TRUSTED_BUCKET:              # confirm the expected source
        raise Exception('event from unexpected bucket')
    key = rec['s3']['object']['key']
    validate_object(bucket, key)              # scan/validate BEFORE processing
    # Where the actor matters, require a verified identity in the object metadata
    # (e.g. a signed token) rather than inferring trust from the trigger type.
    process_import(bucket, key)
```

## 5. Service-to-Service Invocation (serverless.yml + Node.js)

### Vulnerable
```yaml
# Callee trusts a single shared static key passed in a header
functions:
  internalSync:
    handler: sync.handler
    environment:
      SHARED_KEY: super-secret-static-value    # same across envs, never rotated
```
```javascript
// sync.handler:
if (event.headers['x-api-key'] === process.env.SHARED_KEY) { /* allow */ }
// leaks once -> every caller is authenticated; no per-principal identity
```

### Secure
```yaml
# Caller is granted invoke on ONLY the one function; IAM/SigV4 authenticates it
functions:
  caller:
    handler: caller.handler
    iamRoleStatements:
      - Effect: Allow
        Action: lambda:InvokeFunction
        Resource: arn:aws:lambda:us-east-1:1234:function:internalSync
  internalSync:
    handler: sync.handler
    # No shared secret. The platform verifies the calling principal via IAM;
    # internalSync reads the caller identity from the request context, not a header.
```

## What Changed, and Why

| Weakness | Vulnerable | Secure |
|----------|-----------|--------|
| Entry point | Function URL `AuthType: NONE`, bypasses gateway | `aws_iam` auth, or routed through an authorizer |
| Fleet coverage | Some routes have an authorizer, others none | Every route carries the same authorizer |
| Token validation | Decoded only; claims trusted | Signature + `exp` + `aud` + `iss` verified against JWKS |
| Event triggers | Payload trusted as "internal" | Source confirmed, input validated, identity verified |
| Service-to-service | Shared static key in a header | IAM/SigV4 principal, least-privilege invoke |

## Next Steps

- **[Prevention](prevention.md)**: The full entry-point authentication strategy
- **[Attack Vectors](attack-vectors.md)**: How these weaknesses are exploited
- **[Serverless Learning Path](/learn/serverless)**: Continue with the rest of the Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
