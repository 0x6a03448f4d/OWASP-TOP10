# C3: Validate all Input & Handle Exceptions - Code Examples

Each pair below shows an **insecure** implementation and the **secure** version in the same language. They cover the core of C3: validating input, parameterising queries, encoding output, safe parsing, and handling exceptions so they fail closed and leak nothing.

> Recurring theme: notice that the secure versions always do **two** things—validate the input *and* neutralise it at the sink (parameterise or encode). Validation alone never appears as the whole fix.

## Python

### Insecure
```python
from flask import Flask, request, jsonify
import sqlite3, pickle, subprocess

app = Flask(__name__)
app.config["DEBUG"] = True                     # interactive debugger reachable = RCE

@app.route("/user")
def user():
    name = request.args["name"]                # no validation
    db = sqlite3.connect("app.db")
    # SQL injection: input concatenated into the query
    row = db.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchone()
    # XSS: input reflected into HTML with no encoding
    return "<div>Hello, " + name + "</div>"

@app.route("/ping")
def ping():
    host = request.args["host"]
    # Command injection: shell interprets ; && | $()
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return out.stdout

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))     # unsafe deserialization -> RCE

@app.errorhandler(Exception)
def boom(e):
    return jsonify(error=str(e), trace=traceback.format_exc()), 500   # leaks internals
```

### Secure
```python
import re, uuid, logging, subprocess, json
from html import escape
from flask import Flask, request, jsonify, abort
from markupsafe import Markup

app = Flask(__name__)
app.config["DEBUG"] = False                    # no debugger in production
log = logging.getLogger("app")

NAME_RE = re.compile(r"\A[A-Za-z][A-Za-z '\-]{1,49}\Z")   # allow-list, anchored

@app.route("/user")
def user():
    name = request.args.get("name", "")
    if not NAME_RE.fullmatch(name):            # 1) validate (server-side, allow-list)
        abort(400, "invalid name")
    db = get_db()
    # 2a) parameterised query: data sent separately from the command
    row = db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()
    # 2b) context-aware output encoding: input rendered as inert text
    return Markup("<div>Hello, {}</div>").format(name)   # auto-escapes

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):   # validate host
        abort(400, "invalid host")
    # argument array + shell=False: no shell to interpret metacharacters
    out = subprocess.run(["ping", "-c", "1", host], shell=False,
                         capture_output=True, timeout=5)
    return out.stdout

@app.route("/load", methods=["POST"])
def load():
    payload = json.loads(request.data)         # data-only format, never pickle
    return jsonify(ok=True, keys=list(payload.keys()))

@app.errorhandler(Exception)
def boom(e):
    error_id = uuid.uuid4().hex
    log.exception("unhandled error id=%s", error_id)   # detail to logs only
    return jsonify(error="Something went wrong", error_id=error_id), 500  # generic
```

## Node.js

### Insecure
```javascript
const express = require("express");
const app = express();
app.use(express.json());

app.get("/user", (req, res) => {
  const name = req.query.name;                       // no validation
  // SQL injection: string interpolation into the query
  db.query(`SELECT * FROM users WHERE name = '${name}'`, (err, rows) => {
    if (err) return res.status(500).send(err.stack); // leaks stack trace
    // XSS: reflected without encoding
    res.send(`<div>Hello, ${name}</div>`);
  });
});

// NoSQL injection: object body used directly as a filter
app.post("/login", (req, res) => {
  users.findOne({ user: req.body.user, pass: req.body.pass }, (e, u) => {
    res.json({ ok: !!u });    // { "user": {"$ne":null}, "pass": {"$ne":null} } bypasses
  });
});
```

### Secure
```javascript
const express = require("express");
const { z } = require("zod");                        // schema validation
const escapeHtml = require("escape-html");           // context-aware encoding
const app = express();
app.use(express.json({ limit: "100kb" }));

const UserQuery = z.object({
  name: z.string().regex(/^[A-Za-z][A-Za-z '\-]{1,49}$/),   // allow-list, anchored
});

app.get("/user", (req, res, next) => {
  const parsed = UserQuery.safeParse(req.query);     // 1) validate on the server
  if (!parsed.success) return res.status(400).json({ error: "invalid name" });
  const { name } = parsed.data;
  // 2a) parameterised query: placeholders, data passed separately
  db.query("SELECT * FROM users WHERE name = ?", [name], (err, rows) => {
    if (err) return next(err);
    // 2b) output encoding: input rendered as text, not markup
    res.send(`<div>Hello, ${escapeHtml(name)}</div>`);
  });
});

const Login = z.object({                             // force strings -> kills $ne bypass
  user: z.string().max(64),
  pass: z.string().max(128),
});

app.post("/login", (req, res, next) => {
  const parsed = Login.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid credentials" });
  const { user, pass } = parsed.data;                // guaranteed strings, not operators
  users.findOne({ user }, (e, u) => {
    if (e) return next(e);
    res.json({ ok: !!u && verifyHash(pass, u.hash) });
  });
});

// Central error handler: fail closed, generic body, detail to logs only
app.use((err, req, res, next) => {
  console.error(err);                                // server log only
  res.status(500).json({ error: "Something went wrong" });
});
```

## Java

### Insecure
```java
@RestController
class UserController {

  @GetMapping(value = "/user", produces = "text/html")
  String user(@RequestParam String name) throws Exception {
    Connection c = ds.getConnection();
    // SQL injection: concatenated statement
    Statement st = c.createStatement();
    ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    // XSS: reflected without encoding
    return "<div>Hello, " + name + "</div>";
  }

  @PostMapping("/import")
  String importXml(@RequestBody String xml) throws Exception {
    // XXE: default parser resolves external entities
    DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xml)));
    return doc.getDocumentElement().getTextContent();
  }

  @ExceptionHandler(Exception.class)
  ResponseEntity<String> onError(Exception e) {
    return ResponseEntity.status(500).body(e.toString());   // leaks internals
  }
}
```

### Secure
```java
@RestController
class UserController {

  private static final Logger log = LoggerFactory.getLogger(UserController.class);
  private static final Pattern NAME = Pattern.compile("\\A[A-Za-z][A-Za-z '\\-]{1,49}\\z");

  @GetMapping(value = "/user", produces = "text/html")
  String user(@RequestParam String name) throws Exception {
    if (!NAME.matcher(name).matches()) {                    // 1) validate, allow-list
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid name");
    }
    try (Connection c = ds.getConnection();
         // 2a) PreparedStatement: parameter bound separately from the SQL
         PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE name = ?")) {
      ps.setString(1, name);
      ResultSet rs = ps.executeQuery();
      // 2b) output encoding via OWASP Java Encoder
      return "<div>Hello, " + Encode.forHtml(name) + "</div>";
    }
  }

  @PostMapping("/import")
  String importXml(@RequestBody String xml) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    // Disable DTDs and external entities -> no XXE
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    f.setFeature("http://xml.org/sax/features/external-general-entities", false);
    f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    f.setXIncludeAware(false);
    f.setExpandEntityReferences(false);
    Document doc = f.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    return doc.getDocumentElement().getTextContent();
  }

  @ExceptionHandler(Exception.class)
  ResponseEntity<Map<String,String>> onError(Exception e) {
    String id = UUID.randomUUID().toString();
    log.error("unhandled error id={}", id, e);              // detail to logs only
    return ResponseEntity.status(500)
        .body(Map.of("error", "Something went wrong", "error_id", id));  // generic
  }
}
```

## What Changed, and Why

| Concern | Insecure | Secure |
|---------|----------|--------|
| Input validation | None; raw input used directly | Server-side, anchored allow-list / schema |
| SQL | String concatenation | Parameterised query / `PreparedStatement` |
| NoSQL | Object body used as filter | Types forced to strings via schema |
| XSS | Reflected unencoded | Context-aware output encoding |
| Commands | `shell=True` with input | Argument array, no shell, validated |
| XML | Default parser (entities on) | DTDs / external entities disabled |
| Deserialization | `pickle.loads` on request | JSON only, no native deserialize |
| Exceptions | Stack trace to client | Fail closed, generic body + logged id |

## Key Takeaways

1. **Validate then neutralise** — every secure handler validates input *and* parameterises/encodes at the sink.
2. **Parameterise, never concatenate** — the real anti-SQLi fix is placeholders, not filtering.
3. **Encode for the context** — HTML output is escaped so input renders as text.
4. **Configure parsers safely** — disable XXE; never native-deserialize untrusted data.
5. **Fail closed, leak nothing** — generic client errors, full detail in server logs only.

## Next Steps

- **[How to Implement](prevention.md)**: The full layered implementation guide
- **[Threats Addressed](attack-vectors.md)**: The attack classes these patterns defeat
- **[Proactive Controls](/learn/proactive)**: Return to the full control set
- **[Practice](/practice)**: Apply what you have learned
