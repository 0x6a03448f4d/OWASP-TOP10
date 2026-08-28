# API08: Security Misconfiguration - Code Examples

Each pair below shows a **vulnerable** configuration and the **secure** version in the same framework. The examples focus on the misconfigurations that dominate real API findings: debug mode, verbose errors, wildcard CORS, and missing security headers.

## Flask (Python)

### Vulnerable
```python
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
app.config['DEBUG'] = True            # interactive debugger reachable = RCE
CORS(app, supports_credentials=True)  # reflects ANY origin with credentials

@app.route('/api/me')
def me():
    return jsonify(load_current_user())   # unhandled errors return full traceback

if __name__ == '__main__':
    app.run(host='0.0.0.0')           # debug server exposed on all interfaces
```

### Secure
```python
import logging, uuid
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config['DEBUG'] = False           # no debugger in production
log = logging.getLogger('app')

ALLOWED_ORIGINS = {'https://app.example.com'}

@app.after_request
def secure_headers(resp):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:                     # exact-match allow-list only
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Vary'] = 'Origin'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    resp.headers.pop('Server', None)
    return resp

@app.errorhandler(Exception)
def handle_error(e):
    err_id = uuid.uuid4().hex
    log.exception('error id=%s', err_id)              # detail to logs, not client
    return jsonify({'error': 'Internal server error', 'error_id': err_id}), 500
```

## Express (Node.js)

### Vulnerable
```javascript
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());                       // Access-Control-Allow-Origin: * for everyone
// x-powered-by banner left on, no security headers

app.get('/api/me', (req, res) => {
    res.json(loadUser());              // throws leak stack traces to the client
});

// Default error handler prints the full stack in the response body
app.listen(3000);
```

### Secure
```javascript
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const app = express();

app.disable('x-powered-by');           // drop the banner
app.use(helmet());                     // HSTS, nosniff, frameguard, CSP baseline
app.use(express.json({ limit: '100kb' }));

const ALLOWED = new Set(['https://app.example.com']);
app.use(cors({
    origin: (origin, cb) => (!origin || ALLOWED.has(origin))
        ? cb(null, true) : cb(new Error('Origin not allowed')),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE']   // no TRACE / wildcard
}));

app.get('/api/me', (req, res, next) => {
    try { res.json(loadUser()); } catch (e) { next(e); }
});

// Central error handler: generic body, detail to logs only
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(3000);
```

## Spring Boot (Java)

### Vulnerable
```java
// application.properties
server.error.include-stacktrace=always      // stack traces in every error body
management.endpoints.web.exposure.include=*  // /actuator/env, /heapdump exposed
spring.h2.console.enabled=true               // dev console reachable

@RestController
class MeController {
    @CrossOrigin(origins = "*")             // wildcard CORS on the endpoint
    @GetMapping("/api/me")
    public User me() { return loadUser(); } // exceptions bubble up verbosely
}
```

### Secure
```java
// application.properties
server.error.include-stacktrace=never
server.error.include-message=never
management.endpoints.web.exposure.include=health,info   // nothing sensitive
management.endpoint.health.show-details=never
spring.h2.console.enabled=false
server.tomcat.max-swallow-size=2MB

@RestController
class MeController {
    // Allow-listed origins only, declared centrally via CorsConfigurationSource
    @GetMapping("/api/me")
    public User me() { return loadUser(); }
}

@ControllerAdvice
class ErrorHandler {
    private static final Logger log = LoggerFactory.getLogger(ErrorHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String,String>> handle(Exception e) {
        String id = UUID.randomUUID().toString();
        log.error("error id={}", id, e);            // detail to logs only
        return ResponseEntity.status(500)
            .body(Map.of("error", "Internal server error", "error_id", id));
    }
}
```

## ASP.NET Core (C#)

### Vulnerable
```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));  // wildcard CORS
var app = builder.Build();

app.UseDeveloperExceptionPage();       // full stack traces returned to clients
app.UseCors();
// No HSTS, no security headers, banner left on

app.MapGet("/api/me", () => LoadUser());
app.Run();
```

### Secure
```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.WithOrigins("https://app.example.com")   // explicit allow-list
     .AllowCredentials()
     .WithMethods("GET", "POST", "PUT", "DELETE")));
var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error");  // generic handler, no stack trace
    app.UseHsts();
}
app.UseHttpsRedirection();

app.Use(async (ctx, next) =>            // security headers on every response
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    ctx.Response.Headers.Remove("Server");
    await next();
});

app.UseCors();
app.MapGet("/api/me", () => LoadUser());
app.MapGet("/error", () => Results.Problem("Internal server error"));
app.Run();
```

## What Changed, and Why

| Misconfiguration | Vulnerable | Secure |
|------------------|-----------|--------|
| Debug / dev errors | Interactive debugger, full stack traces to client | Debug off; generic message + logged `error_id` |
| CORS | `*` or reflected origin with credentials | Exact-match origin allow-list, scoped methods |
| Security headers | Missing | HSTS, `nosniff`, frame denial, CSP on every response |
| Management/banners | Actuator `*`, `X-Powered-By`, `Server` exposed | Only `health`/`info`; banners removed |

## Next Steps

- **[Prevention](prevention.md)**: The full layered hardening strategy
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are exploited
- **[Hands-On Lab](lab/api08-misconfig-lab/)**: Practice fixing a misconfigured API
