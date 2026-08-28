# API09: Improper Inventory Management - Code Examples

Each example contrasts a **vulnerable** pattern — an unversioned or undocumented endpoint with no lifecycle governance — against a **secure** one that enforces supported versions, blocks retired versions with `410 Gone`, and keeps diagnostic routes out of production. The point is not just to add a version number, but to make the inventory *enforceable in code*.

## Flask (Python)

### Vulnerable
```python
from flask import Flask, jsonify
app = Flask(__name__)

# Old, unversioned handler nobody remembers -- no auth, still live
@app.route('/api/users/<int:uid>')
def get_user(uid):
    return jsonify(db.get_user(uid))   # any version, any client, full record

# Debug helper left in from development
@app.route('/_debug')
def debug():
    return jsonify(dict(app.config))   # dumps secrets in production
```

### Secure
```python
from flask import Flask, jsonify, request, g
app = Flask(__name__)

SUPPORTED_VERSIONS = {'v3'}
RETIRED_VERSIONS   = {'v1', 'v2'}
IS_PRODUCTION      = app.config['ENV'] == 'production'

@app.before_request
def enforce_inventory():
    parts = request.path.split('/')          # /api/v3/users/1
    version = parts[2] if len(parts) > 2 else None
    if version in RETIRED_VERSIONS:
        return jsonify({'error': f'API {version} was retired. Use v3.'}), 410
    if version not in SUPPORTED_VERSIONS:
        return jsonify({'error': 'Unsupported API version'}), 404

@app.route('/api/v3/users/<int:uid>')
@require_auth                                  # same control on every route
def get_user(uid):
    if uid != g.current_user.id and not g.current_user.is_admin:
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify(db.get_user(uid))

# Diagnostic routes only registered outside production
if not IS_PRODUCTION:
    @app.route('/_debug')
    def debug():
        return jsonify(dict(app.config))
```

## Express (Node.js)

### Vulnerable
```javascript
const app = require('express')();

// v1 shipped years ago with no auth; never turned off
app.get('/api/v1/orders/:id', (req, res) => {
    res.json(db.getOrder(req.params.id));   // legacy path, weak checks
});

// Swagger UI mounted in every environment
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openapiSpec));
```

### Secure
```javascript
const app = require('express')();

const SUPPORTED = new Set(['v3']);
const RETIRED   = new Set(['v1', 'v2']);

app.param('version', (req, res, next, version) => {
    if (RETIRED.has(version)) {
        return res.status(410).json({ error: `API ${version} retired. Use v3.` });
    }
    if (!SUPPORTED.has(version)) {
        return res.status(404).json({ error: 'Unsupported API version' });
    }
    next();
});

app.get('/api/:version/orders/:id', requireAuth, (req, res) => {
    const order = db.getOrder(req.params.id);
    if (order.ownerId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    res.json(order);
});

// Interactive docs only when explicitly enabled outside production
if (process.env.NODE_ENV !== 'production') {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openapiSpec));
}
```

## Spring Boot (Java)

### Vulnerable
```java
@RestController
public class UserController {

    // Old controller, no version, no auth annotation
    @GetMapping("/api/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);       // reachable by anyone
    }
}
// application.properties: management.endpoints.web.exposure.include=*
```

### Secure
```java
@RestController
@RequestMapping("/api/v3")                       // explicit, current version
public class UserV3Controller {

    @GetMapping("/users/{id}")
    @PreAuthorize("#id == authentication.principal.id or hasRole('ADMIN')")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);
    }
}

// Retired versions fail closed with 410
@RestController
@RequestMapping({"/api/v1/**", "/api/v2/**"})
class RetiredVersionController {
    @RequestMapping
    ResponseEntity<?> gone() {
        return ResponseEntity.status(HttpStatus.GONE)
                .body(Map.of("error", "This API version is retired. Use v3."));
    }
}
// application-prod.properties:
// management.endpoints.web.exposure.include=health
// management.endpoint.health.show-details=never
```

## ASP.NET Core (C#)

### Vulnerable
```csharp
[ApiController]
[Route("api/products")]                          // no version, no [Authorize]
public class ProductsController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Get(int id) => Ok(_db.GetProduct(id));
}

// Program.cs -- Swagger always on
app.UseSwagger();
app.UseSwaggerUI();
```

### Secure
```csharp
[ApiController]
[Authorize]
[Route("api/v{version:apiVersion}/products")]
[ApiVersion("3.0")]
public class ProductsV3Controller : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Get(int id)
    {
        var product = _db.GetProduct(id);
        if (product.OwnerId != User.GetId()) return Forbid();
        return Ok(product);
    }
}

// Retired versions are explicitly gone
[ApiController]
[Route("api/v{version:apiVersion}/products")]
[ApiVersion("1.0")]
[ApiVersion("2.0")]
public class ProductsRetiredController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Gone(int id) =>
        StatusCode(410, new { error = "This API version is retired. Use v3." });
}

// Program.cs -- docs only outside production
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
```

## The Common Pattern

Across all four stacks the secure version does the same three things:

1. **Declares supported and retired versions explicitly**, so the set of live endpoints is defined in code rather than by accident.
2. **Fails closed for retired versions** with `410 Gone` — a decommissioned version cannot silently keep serving data.
3. **Gates diagnostic/documentation endpoints on the environment**, so debug routes and interactive specs never reach production.

Pair these code-level guards with the program-level controls in the [Prevention](prevention.md) guide — an inventory-as-code catalog, external discovery, and gateway parity — so the inventory stays accurate as the system evolves.

## Next Steps

- **[Prevention](prevention.md)**: Build the surrounding inventory and governance program
- **[Attack Vectors](attack-vectors.md)**: See how unmanaged endpoints are discovered and exploited
- **[Hands-On Lab](lab/api09-inventory-lab/)**: Practice discovering and retiring unmanaged endpoints
