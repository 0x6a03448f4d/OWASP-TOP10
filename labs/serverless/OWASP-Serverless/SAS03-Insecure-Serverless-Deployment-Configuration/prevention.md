# SAS-3: Insecure Serverless Deployment Configuration - Prevention

## Prevention Strategy Overview

Preventing serverless misconfiguration is less about a single control and more about **making a private, encrypted, least-privilege deployment the only state that ships**:

1. Make every resource private by default—no public buckets, no wildcard principals, no no-auth URLs.
2. Scope every resource-based policy to a named principal with conditions.
3. Move secrets into a manager and encrypt everything at rest and in transit.
4. Scan the infrastructure as code on every change so drift fails the pipeline.
5. Apply least privilege to both the execution role and the deploy role.

### Core Principles

- **Secure by default**: the deployed default must be the private one; making a resource public should be explicit, rare, and reviewed.
- **Configuration as code**: capture the intended secure state in IaC so it is identical everywhere and reviewable in version control.
- **Least privilege everywhere**: every permission, trigger, and public surface is attack surface—remove what you don't need.
- **Encrypt and enforce transport**: KMS at rest, TLS in transit, and an explicit deny on unencrypted access.

## 1. Private-by-Default Storage

Block public access at the account and bucket level, encrypt, and enforce TLS.

```yaml
# serverless.yml — SECURE bucket
resources:
  Resources:
    UploadsBucket:
      Type: AWS::S3::Bucket
      Properties:
        PublicAccessBlockConfiguration:
          BlockPublicAcls: true
          BlockPublicPolicy: true
          IgnorePublicAcls: true
          RestrictPublicBuckets: true
        BucketEncryption:
          ServerSideEncryptionConfiguration:
            - ServerSideEncryptionByDefault:
                SSEAlgorithm: aws:kms
                KMSMasterKeyID: !Ref DataKey
    UploadsBucketPolicy:
      Type: AWS::S3::BucketPolicy
      Properties:
        Bucket: !Ref UploadsBucket
        PolicyDocument:
          Statement:
            - Sid: DenyInsecureTransport
              Effect: Deny
              Principal: "*"
              Action: "s3:*"
              Resource: !Sub "${UploadsBucket.Arn}/*"
              Condition:
                Bool: { "aws:SecureTransport": "false" }
```

Enable **Block Public Access at the account level** as well, so a future bad bucket policy cannot take effect.

## 2. Scan Infrastructure as Code

Manual review does not scale across dozens of resources. Add automated gates on every pull request.

```bash
# In CI: fail the build on insecure serverless configuration
# 1) Generic IaC / policy scanning
checkov -d . --framework serverless cloudformation terraform

# 2) CloudFormation / SAM specific rules
cfn-nag_scan --input-path ./template.yaml

# 3) Terraform static analysis
tfsec ./infra

# 4) Serverless Framework policy plugin (least-privilege + public-resource checks)
serverless deploy --stage ci --conceal   # with serverless-policy / safeguards
```

Run these on every change and on a schedule against deployed stacks, so newly introduced public resources and configuration drift are caught quickly. Treat a `Principal: "*"`, a public bucket, or an `AuthType: NONE` finding as a build failure.

## 3. Scope Resource-Based Policies

Never grant to `Principal: "*"`. Name the exact principal and add conditions.

```yaml
# AWS SAM — SECURE Lambda permission (scoped to one source)
ProcessOrdersPermission:
  Type: AWS::Lambda::Permission
  Properties:
    FunctionName: !Ref ProcessOrdersFunction
    Action: lambda:InvokeFunction
    Principal: apigateway.amazonaws.com          # not "*"
    SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${Api}/*"
```

```json
// SECURE SQS access policy — specific account + condition, not "*"
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789012:role/producer-role" },
  "Action": "sqs:SendMessage",
  "Resource": "arn:aws:sqs:us-east-1:123456789012:jobs",
  "Condition": { "ArnEquals": { "aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:orders" } }
}
```

Apply the same rule to SNS topic policies and API Gateway resource policies: an explicit principal and a condition, never a wildcard.

## 4. Authenticate Function URLs and APIs

Prefer no Function URL at all. If you need one, require IAM auth.

```yaml
# AWS SAM — SECURE Function URL
ProcessFunction:
  Type: AWS::Serverless::Function
  Properties:
    FunctionUrlConfig:
      AuthType: AWS_IAM            # never NONE for sensitive functions
      Cors:
        AllowOrigins: ["https://app.example.com"]   # explicit, not "*"
        AllowCredentials: false
```

For API Gateway, attach an authorizer (IAM, Cognito, or a Lambda authorizer) and reject unauthenticated requests at the edge.

## 5. Secrets Management and Encryption

Keep secrets out of environment variables. Pull them at runtime from a manager (see also SAS-7 for the full treatment).

```yaml
# SECURE — reference secrets, do not inline them; encrypt env with a CMK
ProcessFunction:
  Type: AWS::Serverless::Function
  Properties:
    KmsKeyArn: !GetAtt EnvKey.Arn          # customer-managed key for env vars
    Environment:
      Variables:
        DB_SECRET_ARN: !Ref DbSecret       # ARN only — resolved at runtime
        CONFIG_PARAM: /prod/app/config     # SSM parameter path, not the value
```

```python
# At runtime: fetch the secret, never store it in the deployment
import boto3, json
sm = boto3.client("secretsmanager")
secret = json.loads(sm.get_secret_value(SecretId=os.environ["DB_SECRET_ARN"])["SecretString"])
```

Use AWS Secrets Manager or SSM Parameter Store (SecureString), and grant the function read access only to the specific secret ARNs it needs.

## 6. Enforce Encryption in Transit and at Rest

- **At rest**: set a customer-managed KMS key on buckets, queues, topics, tables, and function environment variables.
- **In transit**: enforce TLS with an `aws:SecureTransport: false` deny on resource policies (as shown above), and use HTTPS-only endpoints.

```yaml
# SECURE SQS queue with CMK encryption
JobsQueue:
  Type: AWS::SQS::Queue
  Properties:
    KmsMasterKeyId: !Ref DataKey
    KmsDataKeyReusePeriodSeconds: 300
```

## 7. Throttling and Quotas

Bound cost and abuse on every public surface.

```yaml
# API Gateway — SECURE throttling + usage plan
ApiUsagePlan:
  Type: AWS::ApiGateway::UsagePlan
  Properties:
    Throttle:
      RateLimit: 50          # steady-state requests/sec
      BurstLimit: 100        # burst ceiling
    Quota:
      Limit: 100000
      Period: DAY
```

Also set a **reserved concurrency** limit on functions so a single endpoint cannot exhaust the account concurrency pool.

```yaml
ProcessFunction:
  Type: AWS::Serverless::Function
  Properties:
    ReservedConcurrentExecutions: 20   # cap blast radius of a flood
```

## 8. Restrict CORS

Never reflect arbitrary origins. Use an explicit allow-list and avoid credentials unless required.

```yaml
Cors:
  AllowOrigins: ["https://app.example.com"]   # exact origins only
  AllowMethods: ["GET", "POST"]
  AllowHeaders: ["Content-Type", "Authorization"]
  AllowCredentials: false                      # never combine "*" with credentials
```

## 9. Least Privilege on Execution and Deploy Roles

Both roles define the blast radius. Scope each to the specific resources and actions it needs.

```yaml
# SECURE execution role — one function, one bucket, one secret
ProcessRole:
  Type: AWS::IAM::Role
  Properties:
    Policies:
      - PolicyName: process-least-privilege
        PolicyDocument:
          Statement:
            - Effect: Allow
              Action: ["s3:GetObject"]
              Resource: !Sub "${UploadsBucket.Arn}/incoming/*"
            - Effect: Allow
              Action: ["secretsmanager:GetSecretValue"]
              Resource: !Ref DbSecret
```

For the **deploy role**, avoid `AdministratorAccess`. Scope it to the CloudFormation/stack resources it manages, and use per-stage roles so a compromised pipeline cannot touch other environments.

## 10. Review Triggers, Networking, and Drift

- **Triggers**: wire each function only to the event sources it genuinely needs; remove leftover S3/SNS/schedule triggers.
- **Networking**: avoid default-VPC exposure and wide-open security groups; place functions that reach private data in a VPC with least-privilege groups.
- **Drift detection**: enable CloudFormation drift detection and alert when live configuration diverges from the template—out-of-band changes are how public resources reappear.

```bash
aws cloudformation detect-stack-drift --stack-name prod-orders
aws cloudformation describe-stack-resource-drifts --stack-name prod-orders \
  --stack-resource-drift-status-filters MODIFIED DELETED
```

## Framework-Specific Hardening

### Serverless Framework

```yaml
provider:
  name: aws
  iam:
    role:
      statements:                      # per-function least privilege, no "*"
        - Effect: Allow
          Action: ["s3:GetObject"]
          Resource: "arn:aws:s3:::acme-uploads/incoming/*"
  environment:
    DB_SECRET_ARN: ${ssm:/prod/db/secret-arn}   # reference, not the secret
plugins:
  - serverless-iam-roles-per-function  # avoid one shared over-broad role
```

### AWS SAM

```yaml
Globals:
  Function:
    Environment:
      Variables:
        LOG_LEVEL: INFO                # avoid DEBUG payload dumps in prod
Resources:
  ProcessFunction:
    Type: AWS::Serverless::Function
    Properties:
      Policies:
        - S3ReadPolicy: { BucketName: !Ref UploadsBucket }   # scoped policy template
        - AWSSecretsManagerGetSecretValuePolicy:
            SecretArn: !Ref DbSecret
```

## Key Takeaways

1. **Private by default** — Block Public Access, no wildcard principals, no no-auth URLs.
2. **Scan the IaC** — checkov, cfn-nag, and tfsec fail the build on public resources and wildcard policies.
3. **Secrets in a manager, everything encrypted** — KMS at rest, TLS enforced in transit, no plaintext env vars.
4. **Bound the abuse** — throttling, quotas, and reserved concurrency on every public surface.
5. **Least privilege on both roles** — scope the execution role and the deploy role; detect drift.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure serverless.yml, SAM, and IaC
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Labs](/practice)**: Apply this hardening hands-on
