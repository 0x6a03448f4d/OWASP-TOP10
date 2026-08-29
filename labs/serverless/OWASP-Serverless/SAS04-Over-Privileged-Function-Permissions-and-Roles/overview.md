# SAS-4: Over-Privileged Function Permissions & Roles - Overview

## Table of Contents
- [What Are Over-Privileged Function Permissions?](#what-are-over-privileged-function-permissions)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What Are Over-Privileged Function Permissions?

**Over-Privileged Function Permissions & Roles** occurs when a serverless function is granted far more identity and access management (IAM) permission than it actually needs to do its job. Instead of being scoped to the one table it reads or the one bucket it writes, the function carries wildcard actions, wildcard resources, broad managed policies, or a single shared role reused across the whole application. The permission the function *holds* is much larger than the permission the function *uses*.

A serverless application is not one process—it is dozens or hundreds of small, independently deployed functions, each with its own execution role. That structure is a security opportunity: every function *could* be locked to exactly the handful of API calls it makes. Over-privilege throws that opportunity away. When a function's role says `"Action": "*"` on `"Resource": "*"`, the function's actual code may only call `dynamodb:GetItem` on one table—but the credentials it is handed can do anything, anywhere, in the account.

### Core Concept

```
Least-Privilege (secure):
  One role PER function
  Actions   -> only the exact API calls the code makes (dynamodb:GetItem)
  Resources -> specific ARNs (arn:aws:dynamodb:...:table/Orders)
  Conditions-> scoped further (aws:SourceArn, encryption context, index)
  Dangerous -> no iam:*, no unscoped iam:PassRole, no *:Delete* it never calls
  Blast radius on compromise -> one table, read-only

Over-Privileged (vulnerable):
  One SHARED role for every function in the app
  Actions   -> wildcards: "*", "s3:*", "dynamodb:*", "lambda:*"
  Resources -> "Resource": "*"  (every bucket, table, function, queue)
  Managed   -> broad AWS managed policies (e.g. *FullAccess) attached
  Dangerous -> iam:PassRole / iam:* present "just in case"
  Blast radius on compromise -> the entire cloud account
```

### Why It's Critical for Serverless

Serverless concentrates several conditions that make over-privilege uniquely dangerous:

- The function's role credentials are **right there in the execution environment**. The platform injects short-lived keys for the role into the function at runtime (environment variables, the instance/credentials endpoint). Any code execution in the function — often via [SAS-1 event-data injection](../SAS01-Function-Event-Data-Injection/overview.md) — can read those credentials and assume the role's full power.
- There are **many functions, so many roles to get wrong**. Copying one permissive template across a fleet propagates the same over-broad role everywhere.
- Functions are **glue between managed services** — they touch storage, databases, queues, secrets, and other functions. A wildcard on any of those services is a wildcard over the whole data plane.
- The identity boundary **is the only boundary**. There is no long-lived host, no network segmentation to fall back on; if the role is broad, the compromise is broad. The IAM policy *is* the security perimeter.

## Why Does This Matter?

### Business Impact

- **Whole-Account Compromise from One Function**: A single injectable or vulnerable function with a broad role becomes a launchpad to read every bucket and table, invoke every other function, and create new resources.
- **Bulk Data Exposure**: `s3:*` or `dynamodb:*` on `*` means one compromised function can exfiltrate every object and every record in the account, not just its own data.
- **Privilege Escalation to Admin**: Permissions like `iam:PassRole`, `iam:AttachRolePolicy`, or `iam:CreatePolicyVersion` let an attacker turn a limited foothold into full administrative control.
- **Resource Abuse and Cost**: Permission to create compute (spin up instances, new functions) is routinely abused for cryptomining, driving large unexpected bills.
- **Compliance and Audit Failure**: Least privilege is an explicit requirement in most frameworks (PCI-DSS, SOC 2, ISO 27001). Wildcard roles are a direct finding.

### Technical Impact

- **Lateral Movement**: The role becomes a pivot — `lambda:InvokeFunction` on `*` lets a compromised function trigger and abuse every other function's logic and data.
- **Persistence**: With `iam:*` or function-management permissions, an attacker can create back-door users, roles, or functions that survive the original fix.
- **Defense Evasion**: Broad permissions may include the ability to disable logging or delete trails, hiding the intrusion.
- **Cross-Service Blast Radius**: A role scoped to "all of DynamoDB and all of S3 and all of SQS" turns a single-service bug into a multi-service breach.
- **Escalation via Trust**: `iam:PassRole` combined with a service that assumes roles lets the attacker borrow a *more* privileged role than the function itself holds.

## Technical Context

### Common Over-Privilege Scenarios in Serverless

#### 1. A Single Shared Execution Role for Every Function

```yaml
# serverless.yml — one broad role at the provider level, inherited by ALL functions
provider:
  name: aws
  iam:
    role:
      statements:
        - Effect: Allow
          Action: "*"          # every function gets every permission
          Resource: "*"        # ...on every resource
functions:
  createOrder:  { handler: create.handler }   # only needs PutItem on Orders
  healthCheck:  { handler: health.handler }   # needs nothing at all
  thumbnailer:  { handler: image.handler }    # only needs S3 on one bucket
```

**Risk**: The `healthCheck` function that needs no permissions carries the same account-wide power as everything else. Compromise the weakest function, own the account.

#### 2. Wildcard Actions and Resources

```json
{
  "Effect": "Allow",
  "Action": ["s3:*", "dynamodb:*"],
  "Resource": "*"
}
```

**Risk**: `s3:*` includes `DeleteBucket`, `PutBucketPolicy`, and read of *every* bucket; `dynamodb:*` includes `DeleteTable` and full scans of every table. The function almost certainly calls two or three of these actions on one resource.

#### 3. Broad AWS Managed Policies

```
Attached to the execution role:
  AmazonS3FullAccess
  AmazonDynamoDBFullAccess
  AWSLambda_FullAccess
```

**Risk**: `*FullAccess` managed policies are convenient and enormous. They grant hundreds of actions across all resources of a service — the opposite of least privilege.

#### 4. Unused Permissions Accumulating Over Time

```
Role granted in 2023: s3:GetObject on report-bucket   # feature since removed
Role granted in 2024: sqs:SendMessage on jobs-queue   # still used
Role granted in 2025: secretsmanager:GetSecretValue   # only used by 1 of 6 functions
```

**Risk**: Permissions are added when features ship but rarely removed when features are deleted. Roles ratchet only upward, so the granted set drifts far past the used set.

#### 5. Privilege-Escalation Permissions (`iam:PassRole` / `iam:*`)

```json
{
  "Effect": "Allow",
  "Action": ["iam:PassRole", "iam:AttachRolePolicy", "iam:CreatePolicyVersion"],
  "Resource": "*"
}
```

**Risk**: These are not data permissions—they are permissions to *rewrite permissions*. Unscoped `iam:PassRole` lets a function hand a powerful role to a service it controls; `iam:AttachRolePolicy` / `CreatePolicyVersion` let it grant itself admin.

#### 6. Cross-Service Over-Permission

```
One function's role bundles:
  dynamodb:*   (data)
  s3:*         (storage)
  sns:*  sqs:* (messaging)
  ec2:*        (compute it never touches)
  kms:Decrypt on *  (every key in the account)
```

**Risk**: Even if each service grant were "only" what the function uses today, bundling many services into one role means any compromise reaches all of them at once.

### Where Over-Privilege Enters

| Source | Typical Over-Privilege | Consequence |
|--------|------------------------|-------------|
| Provider-level role | One shared role with wildcards inherited by all functions | Uniform, account-wide blast radius |
| Hand-written policy | `Action: "*"` / `Resource: "*"` "to make it work" | Function can do anything, anywhere |
| Managed policies | `*FullAccess` attached for convenience | Hundreds of unused actions granted |
| Copy-paste IaC | Permissive template reused across the fleet | Same over-broad role everywhere |
| Permission drift | Grants added per feature, never removed | Used set far smaller than granted set |
| IAM meta-permissions | Unscoped `iam:PassRole` / `iam:*` | Privilege escalation to admin |

## Real-World Impact

The incidents below are described as **classes** of well-documented failure rather than specific named breaches; the pattern is what matters and it recurs across cloud environments.

### Case Class 1: One Compromised Function, Whole-Account Reach

**Over-Privilege**:
- An internet-facing function processes untrusted input and carries a role with `s3:*` and `dynamodb:*` on `Resource: "*"`.
- The function is exploited (for example through event-data injection or a vulnerable dependency), giving the attacker code execution and therefore the role's credentials.

**Impact**:
- Because the role is account-wide, the attacker reads and exfiltrates buckets and tables that have nothing to do with the compromised function — the blast radius is the whole data plane, not the one feature.

**Root Cause**: A wildcard role turned a single-function bug into a full-account data breach. A least-privilege role scoped to the one table would have contained it.

### Case Class 2: Privilege Escalation via `iam:PassRole`

**Over-Privilege**:
- A function's role includes `iam:PassRole` on `*` plus the ability to create or update another compute resource (a new function, a task, an instance).

**Impact**:
- The attacker uses `PassRole` to attach a far more privileged existing role to a resource they create, then operates as that role — escalating well beyond what the original function was ever granted.

**Root Cause**: A permission to *delegate* roles was left unscoped. `PassRole` should always be constrained to specific, minimally-privileged role ARNs with a service condition.

### Case Class 3: Managed `*FullAccess` Policy as the Default

**Over-Privilege**:
- During development, an `*FullAccess` managed policy is attached "to unblock the build" and is never tightened before production.

**Impact**:
- Every function sharing that role can perform hundreds of unused actions across every resource of the service, so any one weak function exposes the entire service to abuse, deletion, or exfiltration.

**Root Cause**: Convenience defaults that were never replaced with a generated, least-privilege policy. Cloud providers now publish least-privilege guidance and analyzers precisely because this pattern is so common.

## Prevalence and Statistics

Over-privileged function permissions are consistently identified as one of the **most common and highest-impact** issues in serverless security assessments, and least-privilege violations are among the most frequent findings in cloud security posture reviews generally.

Rather than cite precise percentages (which vary by source and year), the defensible picture is:

- The **vast majority of function roles grant more than the function uses** — analyzers that compare granted vs. used permissions routinely report large unused surpluses.
- **Wildcards and `*FullAccess` policies are widespread** because they are the path of least resistance when a deployment is failing on a permission error.
- The impact is rated **severe**: over-privilege is rarely the initial entry point, but it is the multiplier that turns a contained bug into an account-wide breach.

> Note: exact figures differ between reports. The durable takeaway is that over-privilege is nearly ubiquitous, easy to introduce, and the single biggest factor in how far an attacker can travel after the first foothold.

## Common Misunderstandings

### Myth 1: "One shared role is simpler, and simpler is safer"

**Reality**: A shared role is simpler to *write* and far more dangerous to *hold*. It gives your least-trusted function the same power as your most-trusted one, so the weakest link defines the blast radius for the whole app.

### Myth 2: "The function code only calls two APIs, so the wildcard is harmless"

**Reality**: Attackers do not run your code—they run *their* code with your role's credentials. What matters is what the role *can* do, not what your handler happens to call.

### Myth 3: "It's an internal/background function, so permissions don't matter"

**Reality**: Internal functions are reached through injected events, poisoned queue messages, compromised dependencies, and lateral movement. An over-privileged background worker is a prime pivot target precisely because it is less scrutinised.

### Myth 4: "We'll tighten the permissions later"

**Reality**: Permissions almost never get tightened after go-live; they only accumulate. The least-privilege policy must be generated and applied *before* production, then enforced so it cannot regress.

### Myth 5: "`iam:PassRole` is just plumbing, not a real permission"

**Reality**: `PassRole` is one of the most abused escalation primitives in the cloud. Unscoped, it lets a low-privileged function borrow a high-privileged role. It must always be constrained to specific role ARNs and a service condition.

### Myth 6: "`*FullAccess` managed policies are AWS-blessed, so they're fine"

**Reality**: Managed `*FullAccess` policies exist for convenience and breadth, not for least privilege. They grant hundreds of actions on all resources—the direct opposite of what a single function needs.

## How Over-Privilege Differs from Related Issues

| Aspect | Over-Privileged Roles (SAS-4) | Event-Data Injection (SAS-1) | Security Misconfiguration |
|--------|-------------------------------|------------------------------|---------------------------|
| **Root cause** | Role grants exceed what the function uses | Untrusted event data reaches a sink | Insecure settings/defaults |
| **What it enables** | Blast radius after a compromise | The initial code execution | Recon and easier footholds |
| **Where it lives** | IAM policy / execution role | Function handler logic | Config of every layer |
| **Typical fix** | Scope the role; one role per function | Validate/parameterise input | Harden and disable |

SAS-1 and SAS-4 are the classic pairing: injection is *how* an attacker gets in, over-privilege is *how far* they get once inside. Fixing one without the other leaves the account exposed.

## Key Takeaways

1. **The role is the perimeter**—in serverless there is no host or network to fall back on, so an over-broad role *is* the breach surface.
2. **What the role can do, not what the code calls**—attackers use the credentials, not your handler.
3. **One least-privilege role per function**—shared and wildcard roles make the weakest function define the blast radius.
4. **Meta-permissions are the crown jewels**—`iam:*` and unscoped `iam:PassRole` convert a foothold into account takeover.
5. **Granted drifts above used**—permissions accumulate, so generate and re-verify least privilege continuously.

## How to Identify if You're Vulnerable

Ask these questions about your serverless application:

- [ ] Does each function have its **own** execution role, or do many functions share one?
- [ ] Do any policies use `"Action": "*"`, `"s3:*"`, `"dynamodb:*"`, or other service wildcards?
- [ ] Do any policies use `"Resource": "*"` where a specific ARN would do?
- [ ] Are any broad `*FullAccess` managed policies attached to execution roles?
- [ ] Is `iam:PassRole` present, and if so, is it scoped to specific role ARNs with a service condition?
- [ ] Are `iam:*` or other permission-editing actions granted to any function?
- [ ] Have you compared *granted* vs. *used* permissions (e.g. with IAM Access Analyzer) and removed the surplus?
- [ ] Are roles separated by trust level and data sensitivity, or does one role touch many services?
- [ ] Are permission boundaries applied to cap what any function role can ever do?
- [ ] Is least privilege enforced in IaC and re-checked on every deploy, or does it drift?

If you answered "no" or "not sure" to several of these, one compromised function likely reaches far more of your account than it should.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers turn a broad role into account-wide compromise
- **[Prevention](prevention.md)**: Build least-privilege, per-function roles that hold the line
- **[Examples](examples.md)**: Vulnerable vs. secure IAM policies and per-function `serverless.yml` roles
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
