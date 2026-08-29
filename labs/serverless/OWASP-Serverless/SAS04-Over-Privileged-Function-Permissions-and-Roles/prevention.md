# SAS-4: Over-Privileged Function Permissions & Roles - Prevention

## Prevention Strategy Overview

Preventing over-privilege is not one control—it is a discipline of **granting each function exactly what it uses and nothing more, then keeping it that way**:

1. Give every function its **own** least-privilege role.
2. Scope actions and resources to specifics—no wildcards.
3. Remove unused permissions and keep granted equal to used.
4. Ban dangerous permissions unless explicitly scoped.
5. Enforce it in IaC, cap it with permission boundaries, and review it continuously.

### Core Principles

- **Least privilege, per function**: the unit of permission is the single function, not the application. One role each.
- **Specific over wildcard**: name the exact actions and the exact resource ARNs; a wildcard is a decision to grant everything you did not think about.
- **Granted equals used**: the goal state is that every granted permission is one the function actually exercises; anything else is removed.
- **Contain the blast radius**: assume the function will be compromised, and size the role so that compromise is boring.

## 1. One Least-Privilege Role Per Function

The single most important control: do not share a role across functions, and do not attach a broad provider-level role that every function inherits. Give each function a role scoped to its own job.

```yaml
# serverless.yml — per-function roles via serverless-iam-roles-per-function
plugins:
  - serverless-iam-roles-per-function

functions:
  createOrder:
    handler: create.handler
    iamRoleStatements:                       # ONLY this function gets these
      - Effect: Allow
        Action: dynamodb:PutItem
        Resource: arn:aws:dynamodb:${aws:region}:${aws:accountId}:table/Orders

  getOrder:
    handler: read.handler
    iamRoleStatements:
      - Effect: Allow
        Action: dynamodb:GetItem            # read-only, separate role
        Resource: arn:aws:dynamodb:${aws:region}:${aws:accountId}:table/Orders

  healthCheck:
    handler: health.handler                  # no iamRoleStatements = no permissions
```

Now compromising `healthCheck` yields nothing, and compromising `getOrder` yields read-only access to one table—not the account.

## 2. No Wildcards: Specific Actions and Resource ARNs

Replace every `*` with an explicit list. Name the actions the code calls and pin them to specific ARNs.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOneBucketPrefix",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::uploads-prod/incoming/*"
    },
    {
      "Sid": "WriteOneTable",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
      "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/Orders"
    }
  ]
}
```

Rules of thumb: never `Action: "*"`, never `service:*`, never `Resource: "*"` for data services. If a resource genuinely cannot be pinned (a few actions do not support resource-level permissions), constrain it with a `Condition` instead.

## 3. Scope Further with Conditions

Conditions tighten a policy beyond action and resource—restricting by source, encryption, or specific sub-resources.

```json
{
  "Effect": "Allow",
  "Action": "dynamodb:Query",
  "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/Orders",
  "Condition": {
    "ForAllValues:StringEquals": {
      "dynamodb:LeadingKeys": ["${aws:userid}"]
    }
  }
}
```

```json
{
  "Effect": "Allow",
  "Action": "sqs:SendMessage",
  "Resource": "arn:aws:sqs:us-east-1:111122223333:jobs",
  "Condition": { "ArnEquals": { "aws:SourceArn": "arn:aws:sns:...:orders-topic" } }
}
```

## 4. Remove Unused Permissions

Granted permission drifts above used permission over time. Close the gap with tooling that compares the two and prunes the surplus.

```bash
# Generate a least-privilege policy from OBSERVED access (CloudTrail):
aws accessanalyzer start-policy-generation \
    --policy-generation-details '{"principalArn":"arn:aws:iam::ACCT:role/FuncRole"}' \
    --cloud-trail-details ...

# Review each role's last-accessed data to find unused services/actions:
aws iam generate-service-last-accessed-details --arn arn:aws:iam::ACCT:role/FuncRole
aws iam get-service-last-accessed-details --job-id <id>
```

IAM Access Analyzer (policy generation and unused-access findings) and least-privilege policy generators turn "what did this role actually use in 90 days?" into a concrete, tighter policy. Re-run on a schedule so roles shrink as features are removed.

## 5. Ban Dangerous Permissions (or Scope Them Hard)

Some permissions are escalation primitives. Treat them as forbidden by default and, where truly needed, scope them tightly.

```
# NEVER on a function role unless deliberately reviewed:
iam:*                       # can rewrite permissions -> admin
iam:PassRole  on  "*"        # can borrow a bigger role
iam:AttachRolePolicy / iam:PutRolePolicy / iam:CreatePolicyVersion
sts:AssumeRole on "*"
```

```json
// If PassRole is genuinely required, constrain it to ONE role + a service condition:
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::111122223333:role/OrdersWorkerRole",
  "Condition": { "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" } }
}
```

## 6. Separate Roles by Trust and Data Sensitivity

Do not let one role span unrelated trust levels or data classes. Split roles so a compromise in a low-sensitivity path cannot reach high-sensitivity data.

```
publicApiFn      -> role: read one non-sensitive table only
paymentsFn       -> role: read/write payments table + one KMS key (separate role)
adminReportFn    -> role: read analytics bucket only

# Anti-pattern: a single role bundling payments + analytics + admin + messaging.
```

The public, internet-facing functions should hold the smallest roles, because they are the most likely to be compromised first.

## 7. Cap Everything with Permission Boundaries

A permission boundary is a ceiling: even if a role's policy grants more, the effective permission is the intersection with the boundary. Attach one to every function role so a mistake—or an attacker with `iam:*`—cannot exceed the cap.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MaxAllowedForAnyFunction",
      "Effect": "Allow",
      "Action": ["dynamodb:*", "s3:*", "sqs:*", "logs:*"],
      "Resource": "*"
    },
    {
      "Sid": "DenyPrivilegeEscalation",
      "Effect": "Deny",
      "Action": ["iam:*", "organizations:*", "account:*"],
      "Resource": "*"
    }
  ]
}
```

Here the boundary explicitly *denies* IAM and org actions to every function that carries it—so even a role that mistakenly grants `iam:*` cannot use it. Boundaries are enforced by requiring that new roles be created with the boundary attached.

## 8. Enforce Least Privilege in Infrastructure as Code

Permissions must live in version control and be reviewed like code, so they cannot be widened by hand in the console.

```yaml
# serverless.yml — provider role kept minimal; per-function roles hold the specifics
provider:
  name: aws
  iam:
    role:
      permissionsBoundary: arn:aws:iam::111122223333:policy/FunctionBoundary

functions:
  thumbnailer:
    handler: image.handler
    iamRoleStatements:
      - Effect: Allow
        Action: [s3:GetObject]
        Resource: arn:aws:s3:::uploads-prod/incoming/*
      - Effect: Allow
        Action: [s3:PutObject]
        Resource: arn:aws:s3:::uploads-prod/thumbnails/*
```

Gate the pipeline on policy scanning so wildcards never merge:

```bash
# CI: fail the build on over-broad IAM in IaC
checkov -d . --check CKV_AWS_1,CKV_AWS_49   # flags Action/Resource "*" statements
cfn-lint template.yaml                       # SAM/CloudFormation policy linting
# Custom guardrail: grep the synthesised policy and reject wildcards
! grep -E '"(Action|Resource)"\s*:\s*"\*"' out/*.json
```

## 9. Continuous Review and Least-Privilege Regression Tests

Least privilege is a moving target as features change. Re-verify it on a cadence, not just at launch.

```bash
# Scheduled: find roles that grant more than they've used, and unused roles entirely
aws accessanalyzer list-findings --analyzer-arn <arn> \
    --filter '{"findingType":{"eq":["UnusedPermission","UnusedIAMRole"]}}'

# Alert when a role gains a wildcard or an iam:* action outside the pipeline
```

Make "granted > used" a finding that must be resolved, so roles trend toward least privilege instead of ratcheting upward.

## 10. Monitoring and Detection

Watch for the signatures of an over-privileged role being *used* the way an attacker would.

```python
# Alert on API calls a function role should never make:
SUSPICIOUS = (
  'iam:CreateUser', 'iam:AttachRolePolicy', 'iam:CreatePolicyVersion',
  'iam:PassRole', 'cloudtrail:StopLogging', 's3:ListAllMyBuckets',
  'ec2:RunInstances', 'lambda:CreateFunction',
)

def flag(event):
    # event from CloudTrail: which role, which action
    if event['eventName'] in SUSPICIOUS and is_function_role(event['userIdentity']):
        alert('Function role used escalation/enumeration API', event)
```

Also enable managed threat detection (for example GuardDuty findings for credential exfiltration and anomalous IAM use), and alert on a function role invoked from outside the function—a strong sign its credentials were harvested.

## Key Takeaways

1. **One role per function** — the unit of least privilege is the single function; never share or inherit a broad role.
2. **Kill the wildcards** — specific actions on specific ARNs, tightened with conditions, is the whole game.
3. **Keep granted equal to used** — generate policies from observed access and prune the surplus continuously.
4. **Forbid escalation permissions** — no `iam:*`, and `PassRole` only when scoped to one role and one service.
5. **Enforce and cap** — least privilege in IaC, permission boundaries as a ceiling, and CI that rejects wildcards.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure IAM policies and per-function `serverless.yml` roles
- **[Attack Vectors](attack-vectors.md)**: Understand the blast radius you're containing
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
