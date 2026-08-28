# API8:2019 Injection - Prevention

## Prevention Strategy Overview

There is one primary defence against injection and everything else is defence-in-depth: **keep untrusted data as data.** Never let request input become part of the command or query text. Concretely:

1. Parameterise every query—prepared statements / bound parameters, always.
2. Use ORMs/ODMs through their safe APIs; never their raw string escape hatches.
3. Validate and strongly type input; reject operator objects and unexpected shapes.
4. Allow-list the things that cannot be parameterised (sort/filter/column/table).
5. Avoid the shell; least-privilege the DB; add a WAF only as an extra layer.

### Core Principles

- **Separate code from data**: parameterisation is the definitive control—the interpreter is told "this is a value," so a payload can never become a command.
- **Positive validation**: define what valid input *is* (type, length, format, allowed set) and reject everything else—far stronger than blocklisting bad characters.
- **Least privilege**: the app's DB/OS identity should be able to do only what the feature needs, so a successful injection has a small blast radius.
- **Defence in depth**: validation, encoding, least privilege, and a WAF each reduce risk, but none replaces parameterisation at the sink.

## 1. Parameterised Queries (the primary fix)

Bind values as parameters so the SQL text is fixed and the input can never alter it.

```
# Python (psycopg / sqlite3) - parameters, never string formatting
cur.execute("SELECT * FROM users WHERE name = %s AND active = %s", (name, True))

// Node (pg / mysql2) - placeholders, values passed separately
db.query('SELECT * FROM users WHERE name = $1 AND active = $2', [name, true]);

// Java (JDBC) - PreparedStatement with bound parameters
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE name = ? AND active = ?");
ps.setString(1, name);
ps.setBoolean(2, true);
```

> Never build SQL with `+`, `%`, `.format()`, f-strings, or template literals. If you are concatenating input into query text, you have an injection bug—regardless of any escaping you added.

## 2. Use ORMs / ODMs Safely

ORMs are safe through their query builders, unsafe through their raw escape hatches.

```
# Django - use the ORM, not raw() with concatenation
User.objects.filter(name=name)                      # safe, parameterised
User.objects.raw("... WHERE name = %s", [name])     # if you must use raw, bind params

# SQLAlchemy - bound parameters, not f-strings
session.execute(text("SELECT * FROM users WHERE name = :n"), {"n": name})

// Prisma - the safe tagged template binds automatically:
prisma.$queryRaw`SELECT * FROM users WHERE name = ${name}`   // safe
// Avoid $queryRawUnsafe with concatenation.
```

Rule: if the ORM method name contains `raw`, `unsafe`, `literal`, or `text`, treat every interpolation as a potential injection and bind parameters instead.

## 3. NoSQL: Type, Cast, and Reject Operators

The NoSQL fix is to guarantee that a field the code expects to be a scalar actually *is* a scalar—never a user-supplied operator object.

```javascript
// Express + Mongoose - force values to strings and reject objects
function scalar(v) {
  if (typeof v !== 'string') throw new Error('invalid input');
  return v;
}
const user = await User.findOne({
  username: scalar(req.body.username),
  password: scalar(req.body.password)   // {"$ne":null} now throws
});

// Reject $-prefixed keys anywhere in the body (operator smuggling):
function rejectOperators(obj) {
  for (const k of Object.keys(obj || {})) {
    if (k.startsWith('$')) throw new Error('operator not allowed');
    if (typeof obj[k] === 'object') rejectOperators(obj[k]);
  }
}
```

Also: disable server-side JavaScript (`$where`, `$function`, `mapReduce`) in the datastore, and configure query sanitisation middleware (for example a sanitiser that strips `$` and `.` from keys) as a second layer.

## 4. Avoid the Shell; Pass Arguments as an Array

The safest command injection defence is to not invoke a shell at all—pass the program and its arguments as a list so metacharacters stay inert data.

```
# Python - no shell, arguments as a list (metacharacters are literal)
import subprocess
subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5, check=True)
# NEVER: os.system("ping -c1 " + host)  /  subprocess.run(cmd, shell=True)

// Node - execFile / spawn with an argument array, not exec
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', host], { timeout: 5000 }, cb);
// NEVER: exec(`ping -c1 ${host}`)
```

If a value must be part of a command, validate it against a strict allow-list first (for example, a hostname regex), and prefer a native library over shelling out entirely.

## 5. Strong Input Validation and Typing

Validate at the API edge with a schema: correct type, length bounds, format, and—critically—reject objects where scalars are expected.

```python
# Python - Pydantic model enforces types and formats
from pydantic import BaseModel, constr

class LoginBody(BaseModel):
    username: constr(strip_whitespace=True, min_length=1, max_length=64)
    password: constr(min_length=1, max_length=200)
# A JSON body sending {"password": {"$ne": null}} fails validation:
# password must be a string.
```

```javascript
// Node - a schema validator (e.g. zod) rejects the wrong shape
const schema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(200)   // object -> validation error
});
const { username, password } = schema.parse(req.body);
```

Positive (allow-list) validation beats negative (blocklist) filtering: define what is valid and reject the rest, rather than trying to enumerate every bad character.

## 6. Allow-List for Sort, Filter, and Column Names

Identifiers—columns, tables, sort directions—cannot be bound as parameters. Map user input through a fixed allow-list to a known-safe value.

```python
# Map the client's sort key to a real column via an allow-list.
SORT_COLUMNS = {"name": "name", "created": "created_at", "price": "price"}
SORT_DIRS    = {"asc": "ASC", "desc": "DESC"}

col = SORT_COLUMNS.get(request.args.get("sort"), "created_at")   # default if unknown
dir = SORT_DIRS.get(request.args.get("dir"), "ASC")
query = f"SELECT * FROM products ORDER BY {col} {dir}"   # values are from a trusted set
# The user never controls the SQL text -- only which pre-approved option is used.
```

The same pattern applies to `fields` (project only allow-listed columns) and `filter` (map to allow-listed columns and a fixed set of operators).

## 7. Escape / Encode for the Target Interpreter (last resort)

When a value genuinely cannot be parameterised (some LDAP/XPath contexts), use the interpreter's dedicated encoder—never hand-rolled string replacement.

```java
// LDAP - encode the value for a search filter (e.g. OWASP ESAPI / library API)
String safe = Encoder.encodeForLDAP(userInput);
String filter = "(&(uid=" + safe + ")(objectClass=person))";

// XML/XPath - prefer a precompiled XPath with variable binding over string building;
// disable external entities on the parser:
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Encoding is interpreter-specific: encoding for SQL does nothing for a shell, and vice versa. Use the right encoder for the exact sink, and only where binding is impossible.

## 8. Least-Privilege Database and OS Accounts

- Give the application a DB account with only the rights it needs—typically `SELECT`/`INSERT`/`UPDATE` on specific tables, never `DROP`, schema, or admin.
- Separate read-only and read-write connections; use the read-only one for query endpoints.
- Run the process as a non-root, unprivileged OS user so a command-injection foothold is contained.
- Disable dangerous datastore features (server-side JS, `xp_cmdshell`, `LOAD_FILE`, stacked queries where not needed).

```sql
-- Grant only what the feature needs
GRANT SELECT, INSERT, UPDATE ON app.orders TO 'api_app'@'%';
-- No DROP, no GRANT, no access to other schemas.
```

## 9. WAF and Runtime Protection (defence-in-depth)

A WAF or RASP can block common injection payloads and buy time, but it is bypassable and must never be the only control.

```
# Treat the WAF as a tripwire and a speed bump, not a fix:
#  - Alert on classic signatures: ' OR 1=1 , UNION SELECT , $ne , $where , ; id
#  - Rate-limit and block sources that trip repeated injection rules
#  - Keep it in front of, not instead of, parameterised code
```

Pair it with logging/alerting on injection signatures and datastore errors, so probing is detected even when it is blocked.

## 10. Testing and Detection

```
# SAST - flag string-built queries and raw escape hatches in code review / CI
semgrep --config p/sql-injection ./src
bandit -r ./app                 # Python: flags shell=True, string SQL, etc.

# DAST / fuzzing - probe live endpoints with injection payloads
# (against systems you own / are authorised to test)
sqlmap -u "https://staging.api.example.com/api/items?id=1" --batch

# Unit tests - assert malicious input is treated as data, not code
assert login({"password": {"$ne": None}}) is UNAUTHENTICATED
```

Run SAST on every pull request, DAST against staging, and add regression tests that feed known payloads (`' OR 1=1`, `{"$ne":null}`, `; id`) and assert they fail safely.

## Framework-Specific Hardening

### Flask (Python)

```python
from pydantic import BaseModel, constr
import subprocess

class Q(BaseModel):
    name: constr(max_length=64)

# Parameterised DB access
cur.execute("SELECT id,email FROM users WHERE name = %s", (q.name,))

# No shell when running external tools
subprocess.run(["convert", src, dst], shell=False, check=True, timeout=10)
```

### Express (Node.js)

```javascript
const { z } = require('zod');
const { execFile } = require('child_process');

// Reject operator objects and wrong types at the edge
const Login = z.object({ username: z.string(), password: z.string() });
const { username, password } = Login.parse(req.body);

// Parameterised query + arg-array command execution
db.query('SELECT id FROM users WHERE username = $1', [username]);
execFile('ping', ['-c', '1', host], { timeout: 5000 }, cb);
```

## Key Takeaways

1. **Parameterise everything** — bound parameters are the one control that makes payloads inert; concatenation is the bug.
2. **Use ORMs/ODMs safely** — the `raw`/`unsafe`/`literal`/`text` escape hatches reintroduce injection.
3. **Type and validate** — reject operator objects and unexpected shapes so NoSQL operator injection can't land.
4. **Allow-list what you can't bind** — sort/filter/column/table names map through a trusted set.
5. **Least privilege + WAF are backups** — they shrink and slow the damage; they never replace parameterisation.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure across frameworks
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[API Security Top 10](/learn/api)**: Back to the full learning path
- **[Practice](/practice)**: Test your skills against injectable endpoints
