# SAS-2: Broken Authentication - Attack Vectors

## Table of Contents
- [Understanding Broken-Authentication Attack Vectors](#understanding-broken-authentication-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining the Weaknesses](#chaining-the-weaknesses)

## Understanding Broken-Authentication Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in serverless applications you own or are authorised to test.

Attacking broken authentication in serverless is rarely about defeating a cryptographic control. It is about **finding the door that was left off the hinges**. The attacker maps the fleet of functions, identifies which entry points skip the central authentication layer, and invokes privileged logic through whichever one is open—a public Function URL, an event trigger, or a direct invoke.

The attacker's goal in this category is usually one of:

- Reach a function **without passing through the API Gateway authorizer** at all.
- Supply an event or payload that a "trusted internal" function will act on without checking the actor.
- Forge or replay identity by exploiting a token check that verifies too little.

### Core Attack Flow

```
1. Enumerate
   ↓
   Discover functions, Function URLs, ARNs, triggers, event sources
2. Probe
   ↓
   Hit each entry point directly; note which respond without auth
3. Bypass
   ↓
   Invoke via Function URL / event source / direct call — skip the gateway
4. Forge / Replay
   ↓
   Craft or reuse tokens where validation is weak or missing
5. Escalate / Exfiltrate
   ↓
   Run privileged logic, read data, pivot with the function's role
```

## Common Attack Patterns

### 1. Invoking an Unauthenticated Function URL

A Lambda Function URL created with `AuthType: NONE` is a public HTTPS endpoint that never touches API Gateway.

```http
GET https://abc123def456.lambda-url.us-east-1.on.aws/?report=all HTTP/1.1

HTTP/1.1 200 OK
{ "records": [ { "email": "victim@corp.com", "ssn": "..." }, ... ] }
```

**Payoff**: privileged logic runs with no credentials. Any authorizer configured on the gateway is irrelevant because the request never reaches it.

### 2. Triggering "Internal" Functions via Their Event Source

A function that assumes its S3 event is trusted will process whatever an attacker can get into the bucket.

```bash
# Attacker uploads to a bucket that fans out to a privileged function
aws s3 cp ./malicious.csv s3://ingest-bucket/incoming/malicious.csv

# The object-created event invokes:
#   process_import(key)  -> parses attacker CSV, writes to the prod database
```

**Payoff**: attacker-controlled input reaches privileged logic with no authenticated actor behind it. The same applies to SNS topics an outsider can publish to, SQS queues fed by upstream systems, and forwarded EventBridge events.

### 3. Direct SDK Invoke of a Function

If any reachable principal can call `lambda:InvokeFunction` and the function does not verify its caller, the gateway is bypassed.

```bash
aws lambda invoke \
  --function-name internalSync \
  --payload '{"action":"grantAdmin","user":"attacker"}' out.json
# internalSync trusts the payload because "only internal callers reach it"
```

**Payoff**: privileged actions with no user authentication—the function assumed it was unreachable from outside.

### 4. Forging a JWT Against Decode-Only Validation

When a function decodes a token but never verifies its signature, the claims are attacker-controlled.

```
# Attacker crafts a token body and base64url-encodes it — no valid signature needed
header  = {"alg":"none","typ":"JWT"}
payload = {"sub":"attacker","role":"admin","scope":"*"}
token   = b64(header) + "." + b64(payload) + "."

GET /admin/export  Authorization: Bearer <token>
-> 200 OK   # function read claims.role === 'admin' without checking the signature
```

**Payoff**: full impersonation and privilege escalation. Watch for `alg: none` acceptance, missing signature verification, and unchecked `exp`/`aud`/`iss`.

### 5. Replaying a Long-Lived or Leaked Token

Tokens with no expiry, or static service secrets, keep working long after they should.

```http
# A token pulled from a log, a client bundle, or a git history:
Authorization: Bearer <non-expiring-token>
-> still valid weeks later — no exp claim, never rotated
```

**Payoff**: persistent access from a single leaked credential, because nothing forces it to expire or rotate.

### 6. Harvesting ARNs and URLs from Client Code and Logs

Endpoints treated as "secret" are routinely exposed.

```
- Function URLs embedded in front-end JavaScript bundles
- ARNs printed in verbose error responses and CloudWatch logs
- URLs leaked through Referer headers to third-party sites
- Endpoints recorded in browser history and shared links
```

**Payoff**: the "obscure" endpoint is discovered, then invoked directly—obscurity was the only control.

### 7. Exploiting Inconsistent Enforcement Across the Fleet

Attackers enumerate every function and target the one that forgot its authorizer.

```http
POST /prod/getProfile     -> 401  (Cognito authorizer)
POST /prod/updateProfile  -> 401  (Cognito authorizer)
GET  /prod/exportData     -> 200  (authorizer never attached)  <- target
```

**Payoff**: one missed route or one differently-deployed function undoes the protection on all the others.

### 8. Abusing Weak Custom Auth Logic

Home-grown authentication inside a function tends to miss cases that a central provider handles.

```javascript
if (event.headers['x-api-key'] === process.env.API_KEY) { /* allow */ }
// Single shared static key, compared non-constant-time,
// logged in plaintext, never rotated, same across all environments
```

**Payoff**: one leaked or guessed key authenticates every request; there is no per-user identity to revoke.

## Chaining the Weaknesses

Individually minor gaps combine into full compromise:

```
ARN leaked in a verbose error   -> attacker learns the function exists
        +
Function URL is AuthType NONE    -> attacker invokes it directly
        +
Function has a broad exec role   -> call reads a private DynamoDB table
        =  unauthenticated bulk data theft, gateway never involved
```

Another common chain:

```
Decode-only JWT check            -> attacker forges {"role":"admin"}
        -> privileged function trusts the forged claim
        -> issues a long-lived token with no exp
        -> replayed indefinitely for persistent access
```

## Key Takeaways

1. **The attack is entry-point discovery, not payload craft**—the weakest door defines your security, not the front one.
2. **Every non-gateway trigger is a bypass candidate**—Function URLs, event sources, and direct invokes all skip the authorizer.
3. **"Internal" functions act on untrusted input**—the event source is transport, not proof of identity.
4. **Decode is not verify**—a token that is not cryptographically checked is attacker-controlled.
5. **Small gaps chain**—a leaked ARN plus an open URL plus a broad role equals a breach with no login at all.

## Next Steps

- **[Prevention Guide](prevention.md)**: Enforce authentication at every entry point
- **[Code Examples](examples.md)**: See secure auth in Lambda and API Gateway
- **[Serverless Learning Path](/learn/serverless)**: Continue with the rest of the Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
