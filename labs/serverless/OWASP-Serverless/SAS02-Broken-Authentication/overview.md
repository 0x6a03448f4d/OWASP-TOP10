# SAS-2: Broken Authentication - Overview

## Table of Contents
- [What is Broken Authentication in Serverless?](#what-is-broken-authentication-in-serverless)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Characteristics](#prevalence-and-characteristics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Broken Authentication in Serverless?

**Broken Authentication** in a serverless application is the failure to consistently and correctly verify *who* (or *what*) is invoking a function, across *every* way that function can be reached. It is not a single missing login form—it is the gap that opens when a highly distributed, stateless collection of functions is protected in some places and left open in others.

Traditional applications have a small number of entry points, usually funnelled through one web server and one authentication layer. Serverless flips that model: an application is a **fleet of small, independently deployable functions**, and each function can be triggered by many different event sources—an API Gateway request, a public Function URL, an S3 object-created event, an SNS or SQS message, an EventBridge rule, a DynamoDB stream, a scheduled timer, or a direct SDK `Invoke` call. Authentication that is enforced at the front-door API Gateway does *nothing* for a function reached through any of the other doors.

### Core Concept

```
Secure Authentication (serverless):
  Every entry point   -> authenticated, no exceptions
  Identity            -> one central provider (e.g. Cognito) for user auth
  Tokens              -> signature + expiry + audience + issuer validated
  Event triggers      -> treated as untrusted; caller/context verified
  Service-to-service  -> signed IAM/SigV4, least-privilege roles
  Function URLs       -> AWS_IAM auth or an authorizer, never open by default

Broken Authentication:
  Some entry points   -> API Gateway authorized, other triggers wide open
  Identity            -> each function rolls its own ad-hoc check
  Tokens              -> decoded but not verified (no signature/expiry check)
  Event triggers      -> assumed "internal", so trusted blindly
  Service-to-service  -> shared static secret, or no auth at all
  Function URLs       -> AuthType NONE, reachable by anyone who finds the URL
```

### Why It's Critical for Serverless

Serverless architecture concentrates several conditions that make authentication uniquely hard to get right:

- It is **many-entry-point by design**. Every function is an independently reachable unit, and a single application can expose dozens of them through a mix of trigger types—so "we put auth on the API" covers only a fraction of the attack surface.
- It is **stateless**. There is no long-lived server session to lean on; identity must be re-established on every invocation, and any function that skips that step is unprotected.
- It **blurs the trust boundary**. Functions triggered by S3, SNS, SQS, or EventBridge feel "internal," but those event sources can be influenced by attacker-controlled input (an uploaded object, a crafted message, a forwarded event), so "internal" is not the same as "authenticated."
- It is **ephemeral and fragmented**. Functions are deployed, renamed, and duplicated rapidly. It is easy for one function in a large fleet to ship with `AuthType: NONE`, an unfinished authorizer, or a copy-pasted weak token check that never gets reviewed.

## Why Does This Matter?

### Business Impact

- **Unauthorized Privileged Actions**: An attacker who reaches a function through an unauthenticated trigger can invoke privileged business logic—issue refunds, change roles, export data—without ever logging in.
- **Data Exposure**: Functions that read from databases or object storage, if reachable without authentication, become open data endpoints.
- **Account Takeover**: Weak custom auth and broken token validation let attackers forge or replay identity and act as other users.
- **Regulatory and Contractual Fallout**: Unauthenticated access to personal data triggers GDPR, HIPAA, and PCI-DSS obligations, fines, and breach notification duties.
- **Financial and Resource Abuse**: Openly invokable functions can be driven at scale, inflating cloud spend and abusing whatever downstream systems they touch.

### Technical Impact

- **Authorizer Bypass**: Reaching a function through a Function URL or a non-gateway trigger sidesteps the API Gateway authorizer entirely.
- **Identity Forgery**: Tokens that are decoded but not cryptographically verified allow attacker-crafted claims (arbitrary `sub`, `role`, or `scope`).
- **Replay and Long-Lived Tokens**: Tokens with no expiry, or credentials that never rotate, keep working long after they should.
- **Trust-Boundary Confusion**: A function that trusts its event because it "came from S3" will act on an object an attacker uploaded.
- **Lateral Movement**: One unauthenticated function with a broad execution role becomes a foothold for reaching other resources in the account.

## Technical Context

### Common Broken-Authentication Scenarios in Serverless

#### 1. Public Function URL with No Auth

```yaml
# serverless.yml — a Lambda exposed directly to the internet
functions:
  adminReport:
    handler: handler.adminReport
    url:
      authorizer: none        # AuthType: NONE — anyone with the URL invokes it
```

The function is now a public HTTPS endpoint. It never passes through API Gateway, so any authorizer configured there is irrelevant.

#### 2. Assuming Event-Triggered Functions Are "Internal"

```python
# A function triggered by an S3 upload assumes the event is trusted
def handler(event, context):
    key = event['Records'][0]['s3']['object']['key']
    # Acts on attacker-influenced key/content with no further checks
    process_and_publish(key)
```

**Risk**: The uploader may be untrusted (public bucket, a partner, a compromised path). The event source is not proof of a trusted, authenticated actor.

#### 3. Tokens Decoded but Not Verified

```javascript
// Broken JWT handling inside a Lambda
const parts = token.split('.');
const claims = JSON.parse(Buffer.from(parts[1], 'base64'));  // decode only
if (claims.role === 'admin') { /* trusted! */ }              // no signature check
```

**Risk**: Anyone can base64-encode `{"role":"admin"}`. Without verifying the signature, expiry, audience, and issuer, the claims are attacker-controlled.

#### 4. Inconsistent Auth Across the Fleet

```
getProfile   -> API Gateway + Cognito authorizer   (protected)
updateProfile-> API Gateway + Cognito authorizer   (protected)
exportData   -> Function URL, AuthType NONE         (WIDE OPEN)
internalSync -> direct Invoke, no caller check       (WIDE OPEN)
```

**Risk**: Attackers enumerate the fleet and target the weakest function, not the front door.

#### 5. Relying on the Obscurity of an ARN or URL

```
https://abc123def456.lambda-url.us-east-1.on.aws/
```

**Risk**: A random-looking URL or ARN is not a secret. URLs leak through logs, referrer headers, client code, and history; obscurity is not authentication.

### Entry Points Where Authentication Is Missed

| Entry Point / Trigger | Typical Broken-Auth Mistake | Consequence |
|-----------------------|-----------------------------|-------------|
| API Gateway | Authorizer on some routes, forgotten on others | Unauthenticated access to specific operations |
| Lambda Function URL | `AuthType: NONE` left in place | Public, bypasses gateway entirely |
| S3 / SNS / SQS / EventBridge | Event treated as inherently trusted | Acts on attacker-influenced input |
| Direct SDK Invoke | No verification of the calling principal | Any principal with invoke rights acts unchecked |
| Custom token logic | Decode without verifying signature/expiry | Identity forgery, privilege escalation |
| Scheduled / stream triggers | Assumed unreachable by outsiders | Privileged logic runs on unverified data |

## Real-World Impact

> The classes below describe recurring, well-documented *patterns* in serverless deployments. They are incident **classes**, not specific named breaches or CVEs.

### Case Class 1: Public Function URLs Reachable Without Auth

**Broken Authentication**:
- Lambda Function URLs (and equivalent direct HTTP triggers on other clouds) are created with the auth type set to none, often for quick testing, and then left that way.
- The function performs privileged work—reading records, generating reports, mutating state—on the assumption it sits behind the gateway.

**Impact**:
- Anyone who discovers or guesses the URL invokes the function directly, with no credentials, bypassing every gateway control.

**Root Cause**: An entry point that skips the central authentication layer, shipped without its own auth. The fix is to require `AWS_IAM` or an authorizer on the URL, or to remove the URL entirely.

### Case Class 2: Trusting "Internal" Event Triggers

**Broken Authentication**:
- Functions triggered by S3, SNS, SQS, or EventBridge treat the event payload as trusted because it "came from AWS."
- The underlying source (an upload bucket, a topic a partner can publish to, a queue fed by another system) is influenced by untrusted actors.

**Impact**:
- Attacker-controlled content flows into privileged logic—processing malicious files, acting on forged message fields, or amplifying downstream calls—without any authenticated identity behind it.

**Root Cause**: Conflating "the trigger is an AWS service" with "the actor is authenticated and authorized." The event source is transport, not identity.

### Case Class 3: Broken or Absent Token Validation

**Broken Authentication**:
- Custom Lambda authorizers or in-function checks decode a JWT and read its claims without verifying the signature, expiry, audience, and issuer.
- Static, long-lived tokens or shared secrets are used for service-to-service calls and never rotated.

**Impact**:
- Attackers forge claims to impersonate any user or role, or replay a leaked long-lived token indefinitely.

**Root Cause**: Treating a token as trustworthy because it is well-formed rather than because it is cryptographically valid and current. The fix is complete verification against the identity provider's keys plus short lifetimes.

## Prevalence and Characteristics

Broken Authentication sits at the top of the OWASP Serverless concerns precisely because the architecture multiplies the number of places authentication must be enforced. Every additional function and every additional trigger type is another opportunity to get it wrong.

Rather than cite precise counts (which vary by source), the defensible picture is:

- The failure is characterised as **common and easy to introduce**—a single function shipped with `AuthType: NONE` or a decode-only token check is enough.
- The most commonly observed sub-issues are **entry points that bypass the gateway, event triggers trusted as "internal," inconsistent enforcement across the fleet, and incomplete token validation**.
- The impact is rated **high**: it ranges from unauthorized data access to full impersonation and privileged action with no login.

> Note: exact percentages differ between reports and years. The durable takeaway is that in serverless the hard part is not *having* authentication—it is enforcing it *consistently at every one of many entry points*.

## Common Misunderstandings

### Myth 1: "The API Gateway authorizer protects everything"

**Reality**: It protects only requests that actually pass through that gateway. Function URLs, direct invokes, and event-source triggers reach the function without ever touching the gateway or its authorizer.

### Myth 2: "Event-triggered functions are internal, so they don't need auth"

**Reality**: S3, SNS, SQS, and EventBridge sources can be influenced by untrusted input. "Triggered by an AWS service" is not the same as "invoked by an authenticated, authorized actor."

### Myth 3: "A random Function URL / ARN is secret enough"

**Reality**: URLs and ARNs leak through client code, logs, referrers, and browser history. Obscurity delays discovery; it never authenticates a caller.

### Myth 4: "If the JWT decodes, the user is who they claim"

**Reality**: Anyone can craft a well-formed JWT. Only verifying the signature, expiry, audience, and issuer against the identity provider's keys establishes trust.

### Myth 5: "Each function can do its own quick auth check"

**Reality**: Ad-hoc per-function checks drift out of sync and leave gaps. A central identity provider and a consistent, reused authorizer are far harder to get wrong across a large fleet.

### Myth 6: "Internal service-to-service calls don't need credentials"

**Reality**: Any principal that can reach an invoke path is a potential caller. Service-to-service calls must be signed (IAM/SigV4) and scoped with least-privilege roles, not left open.

## How Broken Authentication Differs from Related Issues

| Aspect | Broken Authentication (SAS-2) | Broken Authorization (access control) | Security Misconfiguration |
|--------|-------------------------------|---------------------------------------|---------------------------|
| **Core question** | Is the caller who they claim to be? | Is this caller allowed to do this? | Is the platform hardened correctly? |
| **Typical failure** | No/weak identity check at an entry point | Identity known but limits not enforced | Insecure defaults/settings |
| **Typical fix** | Authenticate every entry point, verify tokens | Enforce per-resource permission checks | Harden and disable defaults |
| **Detection** | Enumerate triggers, test each unauthenticated | Test cross-user/cross-role access | Config/IaC scan |

## Key Takeaways

1. **Authentication must hold at every entry point**—the gateway is one door of many; Function URLs, direct invokes, and event triggers are the others.
2. **"Internal" is not "authenticated"**—event sources carry untrusted input and prove nothing about the actor.
3. **Centralise identity**—one provider and a consistently applied authorizer beat per-function improvisation.
4. **Verify tokens fully**—signature, expiry, audience, and issuer, every time; decoding is not verifying.
5. **Assume each function is directly reachable**—and authenticate it as if it is, backed by least-privilege roles so an unauthenticated call can do little.

## How to Identify if You're Vulnerable

- [ ] Have you enumerated *every* trigger for *every* function (gateway, URL, S3, SNS, SQS, EventBridge, streams, schedules, direct invoke)?
- [ ] Is authentication enforced on each of those entry points—not just the API Gateway?
- [ ] Are there any Function URLs with `AuthType: NONE` that reach privileged logic?
- [ ] Do event-triggered functions treat their input as untrusted rather than "internal"?
- [ ] Are tokens verified for signature, expiry, audience, and issuer—not merely decoded?
- [ ] Do you rely on a central identity provider (e.g. Cognito) instead of per-function custom checks?
- [ ] Are service-to-service calls signed (IAM/SigV4) with least-privilege roles?
- [ ] Are tokens short-lived and rotated, with no long-lived shared secrets baked in?
- [ ] Would an unauthenticated invocation of any single function be limited by a tight execution role?
- [ ] Do you avoid treating an ARN or URL as if it were a secret?

If you answered "no" or "not sure" to several of these, you likely have an unauthenticated path into privileged logic today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers reach functions that skip authentication
- **[Prevention](prevention.md)**: Enforce consistent authentication at every entry point
- **[Examples](examples.md)**: Vulnerable vs. secure auth in AWS Lambda and API Gateway
- **[Serverless Learning Path](/learn/serverless)**: Continue with the rest of the Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
