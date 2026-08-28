# API8:2019 Injection - Code Examples

Each pair below shows a **vulnerable** implementation and the **secure** version in the same framework. The examples focus on the injection sinks that dominate real API findings: string-built SQL, NoSQL operator objects, and shelling out with user input.

## Flask (Python)

### Vulnerable
```python
from flask import Flask, request, jsonify
import sqlite3, os

app = Flask(__name__)

@app.route('/api/products')
def products():
    category = request.args.get('category')
    con = sqlite3.connect('shop.db')
    # SQL injection: input concatenated into the query text
    rows = con.execute(
        "SELECT name, price FROM products WHERE category = '" + category + "'"
    ).fetchall()
    return jsonify(rows)

@app.route('/api/convert', methods=['POST'])
def convert():
    name = request.json['filename']
    # Command injection: user input shelled out
    os.system("convert " + name + " /out/" + name + ".png")
    return {'status': 'ok'}
```

### Secure
```python
from flask import Flask, request, jsonify
from pydantic import BaseModel, constr
import sqlite3, subprocess, re

app = Flask(__name__)

SORT_COLUMNS = {"name": "name", "price": "price"}   # allow-list for identifiers

class ConvertBody(BaseModel):
    filename: constr(pattern=r'^[A-Za-z0-9_.-]{1,64}$')   # strict format

@app.route('/api/products')
def products():
    category = request.args.get('category', '')
    sort = SORT_COLUMNS.get(request.args.get('sort'), 'name')   # never user text
    con = sqlite3.connect('shop.db')
    # Parameterised: category is bound as a value, not SQL
    rows = con.execute(
        f"SELECT name, price FROM products WHERE category = ? ORDER BY {sort}",
        (category,)
    ).fetchall()
    return jsonify(rows)

@app.route('/api/convert', methods=['POST'])
def convert():
    body = ConvertBody(**request.get_json())          # rejects metacharacters
    # No shell; arguments passed as a list, so ; | $() stay inert
    subprocess.run(["convert", body.filename, f"/out/{body.filename}.png"],
                   shell=False, check=True, timeout=10)
    return {'status': 'ok'}
```

## Express (Node.js) — SQL and NoSQL

### Vulnerable
```javascript
const express = require('express');
const app = express();
app.use(express.json());

// SQL injection via string concatenation
app.get('/api/users', (req, res) => {
    const name = req.query.name;
    db.query("SELECT id, email FROM users WHERE name = '" + name + "'",
        (err, rows) => res.json(rows));
});

// NoSQL operator injection: raw body object passed into the query
app.post('/api/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,
        password: req.body.password        // {"$ne": null} bypasses the check
    });
    res.json({ ok: !!user });
});

app.listen(3000);
```

### Secure
```javascript
const express = require('express');
const { z } = require('zod');
const app = express();
app.use(express.json());

// Parameterised query: value is bound, not spliced
app.get('/api/users', (req, res) => {
    const name = String(req.query.name ?? '');
    db.query('SELECT id, email FROM users WHERE name = $1', [name],
        (err, result) => res.json(result.rows));
});

// Schema forces strings, so operator objects are rejected before the query
const Login = z.object({
    username: z.string().min(1).max(64),
    password: z.string().min(1).max(200)
});
app.post('/api/login', async (req, res) => {
    const parsed = Login.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid input' });
    const { username, password } = parsed.data;   // guaranteed strings
    const user = await User.findOne({ username });
    const ok = user && await bcrypt.compare(password, user.passwordHash);
    res.json({ ok: !!ok });
});

app.listen(3000);
```

## Spring Boot (Java)

### Vulnerable
```java
@RestController
class UserController {

    @Autowired JdbcTemplate jdbc;

    // SQL injection: request param concatenated into the query
    @GetMapping("/api/users")
    public List<Map<String,Object>> find(@RequestParam String name) {
        String sql = "SELECT id, email FROM users WHERE name = '" + name + "'";
        return jdbc.queryForList(sql);
    }

    // Command injection: host concatenated into a shell command
    @GetMapping("/api/ping")
    public String ping(@RequestParam String host) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(p.getInputStream().readAllBytes());
    }
}
```

### Secure
```java
@RestController
class UserController {

    @Autowired JdbcTemplate jdbc;

    private static final Set<String> SORTABLE = Set.of("name", "email");

    // PreparedStatement via bound parameter (?), identifiers allow-listed
    @GetMapping("/api/users")
    public List<Map<String,Object>> find(@RequestParam String name,
                                         @RequestParam(defaultValue = "name") String sort) {
        String col = SORTABLE.contains(sort) ? sort : "name";   // never raw input
        String sql = "SELECT id, email FROM users WHERE name = ? ORDER BY " + col;
        return jdbc.queryForList(sql, name);                    // name is bound
    }

    // No shell: ProcessBuilder with an argument array + validated host
    @GetMapping("/api/ping")
    public String ping(@RequestParam String host) throws Exception {
        if (!host.matches("^[A-Za-z0-9_.-]{1,253}$"))
            throw new IllegalArgumentException("invalid host");
        Process p = new ProcessBuilder("ping", "-c", "1", host).start();
        return new String(p.getInputStream().readAllBytes());
    }
}
```

## NoSQL Deep-Dive: Rejecting Operator Objects

### Vulnerable (Express + Mongoose)
```javascript
// Query string ?password[$ne]= is parsed into { password: { $ne: '' } }
app.get('/api/account', async (req, res) => {
    const account = await Account.findOne(req.query);   // whole query object trusted
    res.json(account);
});
```

### Secure
```javascript
// Reject any $-prefixed key and coerce to a typed, allow-listed query
function assertNoOperators(obj) {
    for (const k of Object.keys(obj || {})) {
        if (k.startsWith('$') || k.includes('.')) throw new Error('bad key');
        if (obj[k] && typeof obj[k] === 'object') assertNoOperators(obj[k]);
    }
}

app.get('/api/account', async (req, res) => {
    try {
        assertNoOperators(req.query);
        const id = String(req.query.id ?? '');       // build the query yourself
        const account = await Account.findOne({ _id: id });
        res.json(account);
    } catch (e) {
        res.status(400).json({ error: 'invalid input' });
    }
});
```

## What Changed, and Why

| Sink | Vulnerable | Secure |
|------|------------|--------|
| SQL query | Input concatenated into query text | Bound parameters (`?`/`$1`/`%s`) |
| NoSQL query | Raw request object trusted as the query | Type/shape validated; `$`-keys rejected |
| OS command | Shell string built from input | Arg array, no shell, validated value |
| Sort / column | Identifier taken from user text | Mapped through an allow-list |
| Password check | Value compared inside the query | Hash compared in code after lookup |

## Key Takeaways

1. **Bind, don't build** — parameterised queries make injected payloads inert data.
2. **Validate the shape** — forcing fields to strings stops NoSQL operator injection cold.
3. **Kill the shell** — argument arrays with `shell=False` neutralise command metacharacters.
4. **Allow-list identifiers** — columns and sort directions can't be bound, so map them to a trusted set.
5. **Same fix, every language** — the secure versions all separate code from data at the sink.

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence strategy
- **[Attack Vectors](attack-vectors.md)**: How these sinks are exploited
- **[API Security Top 10](/learn/api)**: Back to the full learning path
- **[Practice](/practice)**: Test your skills against injectable endpoints
