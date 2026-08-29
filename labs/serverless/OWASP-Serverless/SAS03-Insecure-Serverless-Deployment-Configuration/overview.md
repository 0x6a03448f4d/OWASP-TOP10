# SAS-3: Insecure Serverless Deployment Configuration - Overview

## Table of Contents
- [What is Insecure Serverless Deployment Configuration?](#what-is-insecure-serverless-deployment-configuration)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insecure Serverless Deployment Configuration?

**Insecure Serverless Deployment Configuration** occurs when the many settings that govern serverless functions—and the cloud resources they depend on—are left at insecure defaults or actively misconfigured. A single function is rarely deployed alone: it arrives with an execution role, environment variables, triggers, a possible public URL, and a web of buckets, queues, topics, tables, and API Gateway routes around it. Each of those has security-relevant knobs, and most of them ship in a state optimised for "works in a demo," not "safe in production."

Unlike a coding bug, this weakness lives in the **deployment artifact**: the `serverless.yml`, the AWS SAM or CloudFormation template, the Terraform module, and the resource-based policies attached to each service. When those files grant public access, wildcard principals, plaintext secrets, or missing encryption, the vulnerability is baked in before the first request ever arrives. Every subsequent deploy faithfully re-creates it.

### Core Concept

```
Secure Deployment:
  Storage       -> S3 Block Public Access ON, bucket policy scoped to the role
  Resource      -> Lambda/SNS/SQS policies name a specific Principal + condition
  policies
  Function URL  -> AuthType: AWS_IAM, or no Function URL at all
  Secrets       -> pulled from Secrets Manager/SSM, env vars KMS-encrypted
  Encryption    -> at rest (KMS) and in transit (TLS) enforced everywhere
  API Gateway   -> throttling + quotas set, only needed stages, no debug logging
  CORS          -> explicit origin allow-list, never "*"
  Deploy role   -> least privilege, scoped to the stack's own resources

Misconfiguration:
  Storage       -> bucket public-read/public-write, ACL: AllUsers
  Resource      -> AddPermission with Principal: "*", public SNS/SQS/API
  policies
  Function URL  -> AuthType: NONE, anonymous invoke of the function
  Secrets       -> DB_PASSWORD in a plaintext environment variable
  Encryption    -> default/none at rest, mixed HTTP endpoints
  API Gateway   -> no throttling, verbose stage, full request/response logging
  CORS          -> Access-Control-Allow-Origin: * with credentials
  Deploy role   -> AdministratorAccess wildcard on every deploy
```

### Why It's Critical for Serverless

Serverless concentrates several conditions that make deployment misconfiguration especially damaging:

- **The configuration *is* the application boundary.** With no long-lived server to harden, the only thing standing between the internet and your data is the IaC and the resource policies. Get those wrong and there is no second wall.
- **Resources are numerous and ephemeral.** A modest app can spin up dozens of functions, buckets, and queues. A single bad template copied across environments multiplies one mistake into many.
- **Public-by-configuration is one line away.** `AuthType: NONE` on a Function URL, or `Principal: "*"` on a policy, turns a private function into an anonymous endpoint with no code change and no obvious warning.
- **The blast radius follows the execution role.** An over-privileged function role means a single compromised function can read every bucket, invoke every function, and rewrite every policy in the account.

## Why Does This Matter?

### Business Impact

- **Data Exposure**: Publicly-readable buckets used as function input/output stores leak backups, uploads, and customer records to anyone who guesses or scrapes the bucket name.
- **Unauthorized Invocation and Tampering**: A wildcard resource policy or a `NONE`-auth Function URL lets an attacker invoke business logic, enqueue messages, or publish events without any credential.
- **Secret Compromise**: Plaintext secrets in environment variables are visible to anyone who can read the function configuration—and are dumped by many recon tools automatically.
- **Cost and Availability Abuse**: Missing throttling and quotas on public functions and API Gateway turn every anonymous request into a bill and a denial-of-service surface.
- **Regulatory Fallout**: Exposed personal data through a misconfigured bucket or endpoint triggers GDPR, HIPAA, and PCI-DSS obligations, fines, and mandatory breach notifications.

### Technical Impact

- **Anonymous Data Access**: Public buckets and `AuthType: NONE` URLs expose data and logic with no authentication step to fail.
- **Cross-Account Access**: `Principal: "*"` on a Lambda, SNS, SQS, or API resource policy grants the entire internet (or every AWS account) the permission you scoped.
- **Information Disclosure**: Verbose stages, debug logging, and unencrypted environment variables reveal secrets, internal identifiers, and payload contents.
- **Privilege Escalation**: An over-broad deploy role or execution role lets one foothold rewrite policies and reach the rest of the account.
- **Man-in-the-Middle**: Missing TLS enforcement and unencrypted data in transit allow interception between functions and their resources.

## Technical Context

### Common Misconfiguration Scenarios in Serverless

#### 1. Publicly-Readable / Writable Storage Buckets

```yaml
# serverless.yml — VULNERABLE
resources:
  Resources:
    UploadsBucket:
      Type: AWS::S3::Bucket
      Properties:
        AccessControl: PublicRead        # anyone can list and read objects
        # No PublicAccessBlockConfiguration -> public policies allowed
```

**Risk**: A bucket used to stage function input/output becomes a public file share. Public-write is worse—attackers plant objects the function later trusts.

#### 2. Overly Permissive Resource-Based Policies

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "lambda:InvokeFunction",
  "Resource": "arn:aws:lambda:us-east-1:123456789012:function:process-orders"
}
```

**Risk**: `Principal: "*"` on a Lambda `AddPermission`, or on an SNS/SQS/API policy, exposes the resource to the whole world. The same anti-pattern appears as public SNS topics and SQS queues.

#### 3. Public Lambda Function URLs with No Auth

```yaml
# AWS SAM — VULNERABLE
FunctionUrlConfig:
  AuthType: NONE                         # anonymous, unauthenticated invoke
  Cors:
    AllowOrigins: ["*"]
```

**Risk**: A Function URL with `AuthType: NONE` is a public HTTPS endpoint that invokes the function for anyone. Combined with `AllowOrigins: ["*"]`, any site can call it from a victim's browser.

#### 4. Plaintext Secrets in Environment Variables

```yaml
# VULNERABLE — secrets in cleartext, no KMS key
Environment:
  Variables:
    DB_PASSWORD: "S3cr3t-Pa55w0rd"
    STRIPE_KEY: "sk_live_51H..."
```

**Risk**: Anyone with `lambda:GetFunctionConfiguration` reads these directly. Without a customer-managed KMS key, they are also stored using only the default service key.

#### 5. Missing Encryption at Rest / In Transit

```yaml
# VULNERABLE — no encryption specified
QueueResource:
  Type: AWS::SQS::Queue
  # No KmsMasterKeyId -> default handling, no CMK
BucketResource:
  Type: AWS::S3::Bucket
  # No BucketEncryption block, no aws:SecureTransport policy
```

**Risk**: Data at rest is unprotected by a managed key, and without an `aws:SecureTransport` deny, clients may reach the resource over plain HTTP.

### Layers Where Serverless Misconfiguration Hides

| Layer | Typical Misconfiguration | Consequence |
|-------|--------------------------|-------------|
| Function config | Plaintext env vars, no KMS, unnecessary triggers | Secret theft, unexpected invocation paths |
| Function URL / API GW | `AuthType: NONE`, no throttling, verbose stage | Anonymous invoke, DoS, info disclosure |
| Resource policies | `Principal: "*"`, public SNS/SQS/bucket policy | Cross-account/public access |
| Object storage | Public-read/write, no Block Public Access | Data exposure, poisoned inputs |
| Encryption | None at rest, no TLS enforcement | Interception, unprotected data |
| IAM roles | Over-broad execution and deploy roles | Account-wide blast radius, escalation |
| Networking | Default VPC exposure, open security groups | Reachable internal resources |

## Real-World Impact

### Case Study 1: Public Cloud Storage Buckets (2017-ongoing)

**Misconfiguration**:
- Object-storage buckets (for example AWS S3) used by serverless functions to stage uploads, exports, and backups were set to allow public or "authenticated users" read access, or carried overly broad bucket policies.
- Block Public Access was not enabled, so a permissive policy or ACL took effect.

**Impact**:
- A long, well-documented class of incidents across many organisations exposed backups, customer records, and internal documents simply because the storage permission was too broad and no automated check flagged it.

**Root Cause**: Access-control defaults and copy-pasted permissive policies, with no scan enforcing private-by-default storage. Providers later added "Block Public Access" defaults and console warnings in direct response to this pattern.

### Case Study 2: Publicly Exposed Serverless Endpoints (class)

**Misconfiguration**:
- Functions were fronted by public Function URLs or API Gateway routes deployed with authentication set to none, or with resource policies naming a wildcard principal.

**Impact**:
- Researchers and attackers repeatedly discovered endpoints that invoked business logic anonymously—triggering processing, enqueuing work, or reading data—without any credential. Where throttling was also absent, the same endpoints doubled as denial-of-service and cost-amplification surfaces.

**Root Cause**: Auth left at a permissive default during prototyping and never tightened before production, with no policy scan to catch `Principal: "*"` or `AuthType: NONE`. Described here as an incident *class*; specifics vary by organisation.

### Case Study 3: Secrets Leaked Through Function Configuration (class)

**Misconfiguration**:
- Database passwords, third-party API keys, and tokens were stored as plaintext Lambda environment variables rather than in a secrets manager, and without a customer-managed KMS key.

**Impact**:
- Any principal with read access to the function configuration—including over-broad roles and some automated recon tooling—could retrieve the live secrets, enabling lateral movement into databases and third-party services.

**Root Cause**: Convenience during development, no separation between configuration and secrets, and no scan flagging cleartext credentials in IaC. Treated here as a recurring class, not a single named breach.

## Prevalence and Statistics

Insecure deployment configuration is consistently among the **most common findings** in serverless security assessments, because it spans every resource a function touches rather than the function code alone.

Rather than cite precise breach counts (which vary by source), the defensible picture is:

- Misconfiguration of storage, resource policies, and endpoint auth is characterised as **highly prevalent and easily detectable**—IaC scanners and simple enumeration find it routinely.
- The most commonly observed sub-issues are **public buckets, wildcard resource policies, no-auth Function URLs, plaintext secrets, and missing throttling**.
- The impact is rated **moderate to severe**: it ranges from information disclosure up to full data exposure and account-wide escalation via over-broad roles.

> Note: exact percentages and record counts differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that serverless misconfiguration is common, cheap to find, and cheap to exploit.

## Common Misunderstandings

### Myth 1: "Serverless is managed, so the provider secures it for me"

**Reality**: The provider secures the platform; **you** own the configuration of your functions, policies, and resources. A public bucket or a `Principal: "*"` policy is entirely your responsibility under the shared-responsibility model.

### Myth 2: "There's no server, so there's nothing to harden"

**Reality**: The hardening simply moved. Instead of OS and web-server settings, you harden IaC, resource policies, encryption keys, and IAM roles. There are *more* independently configured resources, not fewer.

### Myth 3: "A Function URL is fine because the URL is hard to guess"

**Reality**: `AuthType: NONE` means anonymous invoke for anyone who has the URL, and URLs leak through logs, referrers, code, and scanning. Obscurity is not authentication.

### Myth 4: "Environment variables are private to my function"

**Reality**: Any principal that can read the function configuration can read its environment variables. Without a secrets manager and a customer-managed KMS key, plaintext secrets there are effectively shared with every over-broad role.

### Myth 5: "It's internal, so the resource policy can stay open"

**Reality**: `Principal: "*"` is not "internal"—it grants everyone. Internal resources are reached through SSRF, compromised functions, and cross-account paths; scope every policy to a named principal with conditions.

### Myth 6: "We scanned the code, so we're covered"

**Reality**: Code scanning misses deployment misconfiguration entirely. This class lives in `serverless.yml`, SAM/CloudFormation, Terraform, and resource policies—scan the **infrastructure as code** with checkov, cfn-nag, or tfsec.

## How Serverless Deployment Misconfiguration Differs from Related Issues

| Aspect | Deployment Misconfiguration (SAS-3) | Broken Authentication (SAS-2) | Function Injection (SAS-1) |
|--------|--------------------------------------|-------------------------------|----------------------------|
| **Root cause** | Insecure resource/deploy settings | Weak or missing identity checks | Untrusted event data in a sink |
| **Where it lives** | IaC + resource policies | Auth logic and token handling | Function code / event parsing |
| **Typical fix** | Harden IaC, scope policies, encrypt | Enforce and verify identity | Validate and sanitise events |
| **Detection** | IaC scan, policy review | Auth testing | Fuzzing, code review |

## Key Takeaways

1. **The configuration is the security boundary**—with no server to harden, IaC and resource policies are the only wall.
2. **Private by default**—no public buckets, no `Principal: "*"`, no `AuthType: NONE` unless deliberately and narrowly justified.
3. **Secrets belong in a manager**, not in plaintext environment variables; encrypt at rest and in transit.
4. **Scan the infrastructure as code**—checkov, cfn-nag, and tfsec catch these before deploy; code scanners never will.
5. **Least privilege on both roles**—the execution role *and* the deploy role define the blast radius.

## How to Identify if You're Vulnerable

- [ ] Is S3 Block Public Access enabled on every bucket a function uses?
- [ ] Do any resource-based policies (Lambda, SNS, SQS, API) use `Principal: "*"`?
- [ ] Are any Lambda Function URLs configured with `AuthType: NONE`?
- [ ] Are secrets stored in Secrets Manager/SSM instead of plaintext environment variables?
- [ ] Are environment variables encrypted with a customer-managed KMS key?
- [ ] Is encryption at rest (KMS) and in transit (TLS/`aws:SecureTransport`) enforced everywhere?
- [ ] Are throttling limits and quotas set on public API Gateway routes and functions?
- [ ] Is CORS restricted to an explicit origin allow-list rather than `*`?
- [ ] Is the deploy role scoped to the stack's own resources rather than `AdministratorAccess`?
- [ ] Do you scan IaC (checkov/cfn-nag/tfsec) on every pull request?

If you answered "no" or "not sure" to several of these, you likely have exploitable serverless misconfiguration today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers find and exploit serverless misconfiguration
- **[Prevention](prevention.md)**: Build a private-by-default, scanned deployment baseline
- **[Examples](examples.md)**: Vulnerable vs. secure serverless.yml, SAM, and IaC
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Labs](/practice)**: Apply these techniques hands-on
