# SAS-4: Over-Privileged Function Permissions & Roles - Code Examples

Each pair below shows an **over-privileged** configuration and the **least-privilege** version of the same thing. The examples focus on what dominates real serverless findings: shared and wildcard roles, unscoped resources, dangerous IAM meta-permissions, and per-function role definitions in Infrastructure as Code.

## 1. IAM Policy: Wildcard vs. Scoped

### Vulnerable
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DoAnything",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

```json
// Slightly "narrower" but still over-privileged — service-level wildcards:
{
  "Effect": "Allow",
  "Action": ["s3:*", "dynamodb:*"],
  "Resource": "*"
}
```

### Secure
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadIncomingUploadsOnly",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::uploads-prod/incoming/*"
    },
    {
      "Sid": "WriteOrdersTableOnly",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
      "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/Orders",
      "Condition": {
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": ["${aws:userid}"]
        }
      }
    }
  ]
}
```

## 2. serverless.yml: Shared Broad Role vs. Per-Function Roles

### Vulnerable
```yaml
# One provider-level role, inherited by EVERY function.
service: orders-api
provider:
  name: aws
  runtime: nodejs20.x
  iam:
    role:
      statements:
        - Effect: Allow
          Action: "*"              # every function can do everything
          Resource: "*"

functions:
  createOrder: { handler: src/create.handler, events: [{ httpApi: 'POST /orders' }] }
  getOrder:    { handler: src/read.handler,   events: [{ httpApi: 'GET /orders/{id}' }] }
  healthCheck: { handler: src/health.handler, events: [{ httpApi: 'GET /health' }] }
# healthCheck needs NO permissions, yet holds account-wide power like the rest.
```

### Secure
```yaml
# One least-privilege role PER function via serverless-iam-roles-per-function.
service: orders-api
plugins:
  - serverless-iam-roles-per-function
provider:
  name: aws
  runtime: nodejs20.x
  iam:
    role:
      permissionsBoundary: arn:aws:iam::111122223333:policy/FunctionBoundary  # ceiling

functions:
  createOrder:
    handler: src/create.handler
    events: [{ httpApi: 'POST /orders' }]
    iamRoleStatements:
      - Effect: Allow
        Action: dynamodb:PutItem                 # write-only
        Resource: arn:aws:dynamodb:${aws:region}:${aws:accountId}:table/Orders

  getOrder:
    handler: src/read.handler
    events: [{ httpApi: 'GET /orders/{id}' }]
    iamRoleStatements:
      - Effect: Allow
        Action: dynamodb:GetItem                 # read-only, separate role
        Resource: arn:aws:dynamodb:${aws:region}:${aws:accountId}:table/Orders

  healthCheck:
    handler: src/health.handler
    events: [{ httpApi: 'GET /health' }]
    # no iamRoleStatements -> role with logging only, no data access
```

## 3. Cross-Service Bundle vs. Split, Scoped Roles

### Vulnerable
```yaml
# One function whose role bundles four services on "*".
functions:
  paymentWorker:
    handler: src/pay.handler
    iamRoleStatements:
      - Effect: Allow
        Action: ["dynamodb:*", "s3:*", "sqs:*", "kms:*"]  # data+storage+msg+keys
        Resource: "*"                                       # everything
```

### Secure
```yaml
# Same function, each grant pinned to the one resource it touches.
functions:
  paymentWorker:
    handler: src/pay.handler
    iamRoleStatements:
      - Effect: Allow
        Action: [dynamodb:GetItem, dynamodb:UpdateItem]
        Resource: arn:aws:dynamodb:${aws:region}:${aws:accountId}:table/Payments
      - Effect: Allow
        Action: sqs:ReceiveMessage
        Resource: arn:aws:sqs:${aws:region}:${aws:accountId}:payments-jobs
      - Effect: Allow
        Action: kms:Decrypt                                  # ONE key, not kms:*
        Resource: arn:aws:kms:${aws:region}:${aws:accountId}:key/PAYMENTS_KEY_ID
        Condition:
          StringEquals:
            kms:ViaService: dynamodb.${aws:region}.amazonaws.com
```

## 4. Privilege-Escalation Permissions: Unscoped vs. Constrained

### Vulnerable
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:PassRole",
    "iam:AttachRolePolicy",
    "iam:CreatePolicyVersion",
    "lambda:CreateFunction"
  ],
  "Resource": "*"
}
```

### Secure
```json
// If the function must deploy a worker, PassRole is pinned to ONE minimal role
// and locked to the service it may be passed to. No policy-editing actions at all.
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassOnlyTheWorkerRoleToLambda",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::111122223333:role/OrdersWorkerRole",
      "Condition": {
        "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" }
      }
    }
  ]
}
// iam:*, AttachRolePolicy, CreatePolicyVersion are NOT granted — and a
// permission boundary Denies them even if a future edit adds them back.
```

## 5. Permission Boundary as a Hard Ceiling

Attach this boundary to every function role so no role can ever exceed it—even one that mistakenly grants `iam:*`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOnlyAppServices",
      "Effect": "Allow",
      "Action": ["dynamodb:*", "s3:*", "sqs:*", "kms:Decrypt", "logs:*"],
      "Resource": "*"
    },
    {
      "Sid": "HardDenyEscalationAndBlastRadius",
      "Effect": "Deny",
      "Action": [
        "iam:*", "organizations:*", "account:*",
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
        "ec2:RunInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

## What Changed, and Why

| Over-Privilege | Vulnerable | Least-Privilege |
|----------------|-----------|-----------------|
| Role granularity | One shared/provider role for all functions | One scoped role per function |
| Actions | `*` or `service:*` wildcards | Exact actions the code calls |
| Resources | `Resource: "*"` | Specific ARNs, tightened with conditions |
| Cross-service | Many services bundled on `*` | Split, each pinned to one resource |
| IAM meta-perms | Unscoped `iam:PassRole` / `iam:*` | Removed, or `PassRole` to one role + service |
| Ceiling | None — policy is the only limit | Permission boundary denies escalation |

## Next Steps

- **[Prevention](prevention.md)**: The full least-privilege strategy and tooling
- **[Attack Vectors](attack-vectors.md)**: How over-broad roles are exploited
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
