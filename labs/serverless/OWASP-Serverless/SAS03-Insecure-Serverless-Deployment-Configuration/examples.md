# SAS-3: Insecure Serverless Deployment Configuration - Code Examples

Each pair below shows a **vulnerable** deployment configuration and the **secure** version in the same tool. The examples focus on the misconfigurations that dominate real serverless findings: public buckets, wildcard resource policies, no-auth Function URLs, plaintext secrets, and missing throttling.

## Serverless Framework (serverless.yml)

### Vulnerable

```yaml
service: orders-api
provider:
  name: aws
  runtime: python3.12
  iam:
    role:
      statements:
        - Effect: Allow
          Action: "*"                 # over-broad execution role
          Resource: "*"
  environment:
    DB_PASSWORD: "S3cr3t-Pa55w0rd"    # plaintext secret in env var
    STRIPE_KEY: "sk_live_51H..."

functions:
  process:
    handler: handler.process
    url:
      cors: true                      # reflects any origin
      # authorizer omitted -> AuthType: NONE (anonymous invoke)

resources:
  Resources:
    UploadsBucket:
      Type: AWS::S3::Bucket
      Properties:
        AccessControl: PublicRead     # public bucket, no Block Public Access
```

### Secure

```yaml
service: orders-api
provider:
  name: aws
  runtime: python3.12
  environment:
    DB_SECRET_ARN: ${ssm:/prod/db/secret-arn}   # reference, resolved at runtime
plugins:
  - serverless-iam-roles-per-function

functions:
  process:
    handler: handler.process
    iamRoleStatements:                 # least privilege, scoped resources
      - Effect: Allow
        Action: ["s3:GetObject"]
        Resource: "arn:aws:s3:::orders-uploads/incoming/*"
      - Effect: Allow
        Action: ["secretsmanager:GetSecretValue"]
        Resource: ${ssm:/prod/db/secret-arn}
    url:
      authorizer: aws_iam              # AuthType: AWS_IAM, not NONE
      cors:
        allowedOrigins: ["https://app.example.com"]   # explicit allow-list
        allowCredentials: false

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
            - ServerSideEncryptionByDefault: { SSEAlgorithm: aws:kms }
```

## AWS SAM (template.yaml)

### Vulnerable

```yaml
Resources:
  ProcessFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.handler
      Runtime: python3.12
      Environment:
        Variables:
          API_KEY: "live-key-abcdef"          # plaintext secret
      FunctionUrlConfig:
        AuthType: NONE                        # anonymous public endpoint
        Cors:
          AllowOrigins: ["*"]                 # unrestricted CORS
      Policies: AdministratorAccess           # over-broad execution role

  PublicInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref ProcessFunction
      Action: lambda:InvokeFunction
      Principal: "*"                          # world can invoke
```

### Secure

```yaml
Resources:
  EnvKey:
    Type: AWS::KMS::Key
    Properties:
      Description: CMK for function env + data

  ProcessFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.handler
      Runtime: python3.12
      KmsKeyArn: !GetAtt EnvKey.Arn           # env vars encrypted with a CMK
      ReservedConcurrentExecutions: 20        # bound flood blast radius
      Environment:
        Variables:
          API_SECRET_ARN: !Ref ApiSecret      # ARN only, resolved at runtime
      FunctionUrlConfig:
        AuthType: AWS_IAM                      # authenticated invoke
        Cors:
          AllowOrigins: ["https://app.example.com"]
          AllowCredentials: false
      Policies:
        - AWSSecretsManagerGetSecretValuePolicy: { SecretArn: !Ref ApiSecret }
        - S3ReadPolicy: { BucketName: !Ref UploadsBucket }

  ScopedInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref ProcessFunction
      Action: lambda:InvokeFunction
      Principal: apigateway.amazonaws.com      # specific service, not "*"
      SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${Api}/*"
```

## Terraform (S3 + SQS)

### Vulnerable

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "orders-uploads"
  acl    = "public-read"                # public bucket
}

resource "aws_sqs_queue" "jobs" {
  name = "jobs"
  # no kms_master_key_id -> no CMK encryption
}

resource "aws_sqs_queue_policy" "jobs" {
  queue_url = aws_sqs_queue.jobs.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"                    # anyone can send messages
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.jobs.arn
    }]
  })
}
```

### Secure

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "orders-uploads"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}

resource "aws_sqs_queue" "jobs" {
  name              = "jobs"
  kms_master_key_id = aws_kms_key.data.id      # CMK encryption at rest
}

resource "aws_sqs_queue_policy" "jobs" {
  queue_url = aws_sqs_queue.jobs.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.producer.arn }   # named principal
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.jobs.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.orders.arn } }
    }]
  })
}
```

## Resource Policy: TLS Enforcement

### Vulnerable

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::orders-uploads/*"
    }
  ]
}
```

### Secure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowScopedRole",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/process-role" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::orders-uploads/incoming/*"
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::orders-uploads/*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
```

## What Changed, and Why

| Misconfiguration | Vulnerable | Secure |
|------------------|------------|--------|
| Storage | `public-read` bucket, no encryption | Block Public Access + KMS + TLS deny |
| Resource policy | `Principal: "*"` on invoke/send | Named principal + `SourceArn` condition |
| Function URL | `AuthType: NONE`, CORS `*` | `AuthType: AWS_IAM`, explicit origins |
| Secrets | Plaintext env vars | Secret ARN reference + CMK-encrypted env |
| Roles | `AdministratorAccess` / `*` | Least-privilege, scoped policy templates |
| Abuse controls | None | Throttling, quotas, reserved concurrency |

## Next Steps

- **[Prevention](prevention.md)**: The full private-by-default hardening strategy
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are exploited
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Labs](/practice)**: Practice fixing a misconfigured serverless stack
