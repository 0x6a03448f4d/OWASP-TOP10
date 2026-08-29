# SAS-1: Function Event-Data Injection - Prevention

## Prevention Strategy Overview

Preventing event-data injection is one principle applied everywhere: **treat every field of every event as untrusted, regardless of which source produced it**, and then make sure that if one injection ever slips through, the function cannot do much harm. That gives a layered plan:

1. Validate every event against a strict, per-source schema at the top of the handler.
2. Use safe APIs at every sink—parameterised queries, argument arrays, safe parsers.
3. Never execute event data (`eval`, dynamic `require`/`import`, shells).
4. Canonicalise and contain any path, and allow-list any outbound URL.
5. Scope the execution role to least privilege so a missed bug is contained.
6. Detect and monitor injection signatures across all triggers, not just HTTP.

### Core Principles

- **Every source is hostile**: an S3 key, an SNS body, a DynamoDB attribute, and an email subject deserve the same suspicion as an HTTP body.
- **Validate at the boundary**: the first thing a handler does is confirm the event matches the exact shape it expects, then work only with the validated object.
- **Safe construction over sanitisation**: parameterise and use structured APIs rather than trying to escape dangerous characters by hand.
- **Contain the blast radius**: a least-privilege role turns a successful injection from an account breach into a contained failure.

## 1. Validate Every Event Against a Strict Schema

Do not reach into `event['Records'][0][...]` and use the value. First validate the whole event against a schema for that specific source, reject anything that does not match, and then read only from the validated result.

```javascript
// Node.js -- validate an S3 event with a JSON schema (ajv)
const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, removeAdditional: true });

const s3Event = {
  type: 'object',
  required: ['Records'],
  properties: {
    Records: {
      type: 'array', minItems: 1, maxItems: 10,
      items: {
        type: 'object',
        required: ['s3'],
        properties: {
          s3: {
            type: 'object',
            required: ['object'],
            properties: {
              object: {
                type: 'object',
                required: ['key'],
                properties: {
                  // keys we accept: safe chars only, bounded length
                  key: { type: 'string', maxLength: 512,
                         pattern: '^[A-Za-z0-9._/-]+$' }
                }
              }
            }
          }
        }
      }
    }
  }
};
const validate = ajv.compile(s3Event);

exports.handler = async (event) => {
  if (!validate(event)) {
    throw new Error('Rejected event: ' + ajv.errorsText(validate.errors));
  }
  // Only now is it safe to read the key -- it matched the allow-list pattern.
  const key = event.Records[0].s3.object.key;
  // ...
};
```

```python
# Python -- validate an event with a Pydantic model per source
from pydantic import BaseModel, constr, conlist

class S3Object(BaseModel):
    # allow-list pattern: no quotes, no shell metachars, no traversal
    key: constr(pattern=r'^[A-Za-z0-9._/-]+$', max_length=512)

class S3Record(BaseModel):
    s3: dict
    def object_key(self) -> str:
        return S3Object(**self.s3['object']).key

class S3Event(BaseModel):
    Records: conlist(S3Record, min_length=1, max_length=10)

def handler(event, context):
    parsed = S3Event(**event)          # raises on any mismatch
    key = parsed.Records[0].object_key()
    # key is now known-good
```

Validate the *shape* and the *content*: field presence, types, lengths, and a positive character allow-list. Prefer allow-lists (what is permitted) over deny-lists (what is forbidden), which attackers routinely evade.

## 2. Parameterise Every Query

Never build SQL or NoSQL by string concatenation from an event field. Use bound parameters or the driver's structured API.

```javascript
// Node.js -- parameterised SQL (pg)
await client.query(
  'INSERT INTO files (name, owner) VALUES ($1, $2)',
  [key, owner]                         // values are bound, never interpreted
);

// DynamoDB -- structured API, no expression string built from input
await ddb.put({
  TableName: 'files',
  Item: { pk: key, owner },            // values placed as data, not a query
}).promise();
```

```python
# Python -- parameterised SQL (psycopg / sqlite3 style)
cur.execute(
    "INSERT INTO files (name, owner) VALUES (%s, %s)",
    (key, owner),                      # driver binds the parameters safely
)

# MongoDB -- reject operator injection by typing the value as a string
users.find_one({"user": str(user_id)})   # never pass a raw dict from input
```

For NoSQL, the extra danger is *operator* injection (`$ne`, `$gt`, `$where`). Never pass a parsed JSON object straight into a query filter; extract and coerce individual scalar fields you expect.

## 3. Never Execute Event Data

The strongest control against code and command injection is to remove the interpreter entirely.

```javascript
// AVOID -- every one of these turns data into code:
eval(x); Function(x)(); vm.runInThisContext(x);
require(x);                            // dynamic require of an input value
exec(`convert ${x}`);                 // shell string interpolation

// PREFER -- no shell, arguments passed as an array (no shell parsing):
const { execFile } = require('child_process');
execFile('convert', [safeInputPath, safeOutputPath], cb);
```

```python
# Python -- pass args as a list and never use a shell
import subprocess
subprocess.run(
    ['pdftotext', safe_input_path, safe_output_path],
    shell=False, check=True, timeout=10,
)
# Do NOT: os.system(...), subprocess.run(cmd, shell=True), eval(...), exec(...)
```

If you truly need dynamic behaviour, map an allow-listed key to a fixed function—never turn an event string into executable code or a module path.

```javascript
// Dispatch via an allow-list, not dynamic require:
const handlers = { thumbnail: doThumbnail, index: doIndex };
const fn = handlers[event.detail.action];   // undefined if not allow-listed
if (!fn) throw new Error('Unknown action');
await fn(validated);
```

## 4. Contain Paths and Allow-List URLs

For any file path built from an event field (S3 keys, attachment names), canonicalise and confirm the result stays inside the intended directory.

```javascript
// Node.js -- prevent traversal by resolving and checking the prefix
const path = require('path');
const BASE = '/tmp/work';
const target = path.resolve(BASE, path.basename(key));  // basename strips ../
if (!target.startsWith(BASE + path.sep)) throw new Error('Path escape');
```

```python
# Python -- same idea with os.path.realpath
import os
BASE = '/tmp/work'
target = os.path.realpath(os.path.join(BASE, os.path.basename(key)))
if not target.startswith(BASE + os.sep):
    raise ValueError('Path escape')
```

For any outbound request whose URL comes from an event, allow-list the destination and block link-local / metadata ranges to stop SSRF.

```python
# Python -- SSRF guard for an event-supplied URL
from urllib.parse import urlparse
import ipaddress, socket

ALLOWED_HOSTS = {'api.partner.com'}
def safe_fetch(url):
    u = urlparse(url)
    if u.scheme not in ('https',) or u.hostname not in ALLOWED_HOSTS:
        raise ValueError('URL not allowed')
    ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
    if ip.is_private or ip.is_link_local or ip.is_loopback:
        raise ValueError('Blocked internal address')   # blocks 169.254.169.254
    return http_get(url)
```

## 5. Parse XML, JSON, and Email Safely

Disable external entities on every XML parser that touches event data, and bound the size of anything you parse.

```python
# Python -- XXE-safe XML parsing with defusedxml
from defusedxml.ElementTree import fromstring
root = fromstring(body)   # external entities and DTDs are disabled
```

```javascript
// Node.js -- disable entity expansion in the XML parser you use
const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser({ processEntities: false });
const doc = parser.parse(body);
```

For inbound SES email, treat subject, sender, headers, body, and attachment names as fully untrusted: validate them, sanitise attachment filenames with `basename`, and scan/limit attachment content before processing.

## 6. Least-Privilege Execution Role

Injection damage is bounded by the function's IAM role. Give each function its own role, scoped to only the actions and resources it needs.

```yaml
# serverless.yml -- per-function role, not a shared wildcard role
service: file-indexer
provider:
  name: aws
  runtime: nodejs20.x
  # No account-wide provider.iam block granting broad access.

functions:
  indexUpload:
    handler: src/index.handler
    events:
      - s3:
          bucket: uploads
          event: s3:ObjectCreated:*
    iamRoleStatements:
      - Effect: Allow
        Action: [ "s3:GetObject" ]
        Resource: "arn:aws:s3:::uploads/*"     # this one bucket, read only
      - Effect: Allow
        Action: [ "dynamodb:PutItem" ]
        Resource: "arn:aws:dynamodb:*:*:table/files"   # this one table
```

Avoid `"Action": "*"` and `"Resource": "*"`. Deny the function any permission it does not use—especially `iam:*`, `secretsmanager:*`, and `lambda:InvokeFunction`—so a foothold cannot escalate or pivot.

## 7. Defence in Depth for HTTP Triggers

A WAF and API Gateway request validation are worthwhile—but only for the HTTP path. Use them, and remember they do nothing for S3, SNS, SQS, DynamoDB, EventBridge, SES, Kinesis, or IoT triggers.

```yaml
# serverless.yml -- API Gateway request validation for HTTP triggers only
functions:
  api:
    handler: src/api.handler
    events:
      - http:
          path: /files
          method: post
          request:
            schemas:
              application/json: ${file(schemas/create-file.json)}
# This validator NEVER runs for the S3/SNS/SQS/DynamoDB triggers --
# those functions must validate the event themselves (Section 1).
```

> The single most common failure in this category: hardening the HTTP endpoint and assuming the event-driven functions behind it are covered. They are not. Every trigger needs its own in-handler validation.

## 8. Detection and Monitoring

Watch for injection signatures across all sources, not just HTTP logs.

```python
# Flag suspicious event fields before they reach a sink
import re
SUSPICIOUS = re.compile(r"""[;'"`]|--|/\*|\$\{|\.\./|<!ENTITY|169\.254\.169\.254""", re.I)

def screen(field, source):
    if SUSPICIOUS.search(field or ''):
        log.warning('possible injection source=%s field=%r', source, field)
        emit_metric('EventInjectionSuspect', source)
        # depending on policy: reject, quarantine, or alert
```

Also: alert on functions writing outside `/tmp`, on outbound connections to `169.254.169.254` or private ranges, on execution-role credential use from unexpected IPs, and on error spikes in event-driven (non-HTTP) functions—a common sign of payloads being fired at a queue or bucket.

## Defence-in-Depth Summary

| Layer | Control | Stops |
|-------|---------|-------|
| Event boundary | Strict per-source schema validation | Malformed and payload-bearing fields |
| Data sink | Parameterised queries / structured APIs | SQL & NoSQL injection |
| Execution | No `eval`/shell; args as arrays | Code & command injection |
| Filesystem | Canonicalise + contain paths | Path traversal |
| Parsers | Entities off; bounded size | XXE |
| Network | URL allow-list; block metadata | SSRF |
| Identity | Least-privilege per-function role | Blast-radius / lateral movement |
| Operations | Cross-source monitoring | Missed and asynchronous attempts |

## Key Takeaways

1. **Validate every event** against a strict, per-source schema before touching any field.
2. **Parameterise and use safe APIs** at every sink; never build queries or commands by string.
3. **Never execute event data**—no `eval`, no dynamic `require`/`import`, no shell interpolation.
4. **Contain paths and allow-list URLs** to shut down traversal and SSRF to the metadata service.
5. **Scope the role tightly**—least privilege is what keeps a missed injection from becoming an account breach.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Lambda handlers (Node.js & Python)
- **[Attack Vectors](attack-vectors.md)**: Understand what you are defending against
- **[Serverless Security Track](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Range](/practice)**: Harden a vulnerable function hands-on
