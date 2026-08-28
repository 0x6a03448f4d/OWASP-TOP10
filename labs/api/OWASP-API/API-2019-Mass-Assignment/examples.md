# API6:2019 Mass Assignment - Code Examples

Each pair below shows a **vulnerable** endpoint that binds the request body straight to a model, and the **secure** version that binds only an allow-list of fields. The scenario is the same throughout: a `User` model that carries client-editable fields (`username`, `email`) *and* server-controlled fields (`role`, `is_verified`, `balance`). The attack in every case is to append `"role": "admin"` (and friends) to the body.

## Flask + SQLAlchemy (Python)

### Vulnerable
```python
from flask import Flask, request, jsonify
from models import db, User      # User has: username, email, role, is_verified, balance

app = Flask(__name__)

@app.route('/api/users', methods=['POST'])
def create_user():
    # The whole body is unpacked onto the model — every key becomes a column.
    user = User(**request.get_json())     # {"role": "admin"} is bound here
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id, username=user.username, role=user.role), 201

@app.route('/api/users/me', methods=['PATCH'])
def update_me():
    user = current_user()
    for key, value in request.get_json().items():
        setattr(user, key, value)         # merges ANY field: is_verified, balance...
    db.session.commit()
    return jsonify(ok=True)
```

**Why it's vulnerable**: `User(**body)` and the `setattr` merge loop bind every client key. A request with `"role": "admin"` or `"balance": 999999` writes those columns directly.

### Secure
```python
from flask import Flask, request, jsonify
from pydantic import BaseModel, EmailStr, ConfigDict, ValidationError
from models import db, User

app = Flask(__name__)

class UserCreateDTO(BaseModel):
    model_config = ConfigDict(extra='forbid')   # unknown keys -> error
    username: str
    email: EmailStr
    password: str

class UserUpdateDTO(BaseModel):
    model_config = ConfigDict(extra='forbid')
    display_name: str | None = None              # only editable fields exist here

@app.route('/api/users', methods=['POST'])
def create_user():
    try:
        dto = UserCreateDTO(**request.get_json())
    except ValidationError as e:
        return jsonify(error='invalid input', detail=e.errors()), 400

    user = User(username=dto.username, email=dto.email)
    user.set_password(dto.password)
    user.role = 'user'                # server sets sensitive fields itself
    user.is_verified = False
    user.balance = 0
    db.session.add(user); db.session.commit()
    return jsonify(id=user.id, username=user.username), 201

@app.route('/api/users/me', methods=['PATCH'])
def update_me():
    dto = UserUpdateDTO(**request.get_json())     # role/balance simply don't exist
    user = current_user()
    if dto.display_name is not None:
        user.display_name = dto.display_name
    db.session.commit()
    return jsonify(ok=True)
```

**What changed**: an input DTO with `extra='forbid'` is the only thing the client can populate; sensitive fields are assigned by the server. Injecting `"role":"admin"` now raises a validation error instead of being persisted.

## Express + Mongoose (Node.js)

### Vulnerable
```javascript
const express = require('express');
const User = require('./models/User');   // fields: username, email, role, isVerified, balance
const app = express();
app.use(express.json());

app.post('/api/users', async (req, res) => {
    // The entire body is handed to the model constructor.
    const user = new User(req.body);      // { role: "admin" } is bound here
    await user.save();
    res.status(201).json(user);
});

app.patch('/api/users/me', async (req, res) => {
    const user = await User.findById(req.userId);
    Object.assign(user, req.body);        // merges ANY field: isVerified, balance...
    await user.save();
    res.json(user);
});
```

**Why it's vulnerable**: `new User(req.body)` and `Object.assign(user, req.body)` copy every key from the untrusted body onto the document, including `role`, `isVerified`, and `balance`.

### Secure
```javascript
const express = require('express');
const { z } = require('zod');
const User = require('./models/User');
const app = express();
app.use(express.json());

// Allow-list schemas: only these keys are accepted; unknown keys are stripped/rejected.
const CreateUser = z.object({
    username: z.string().min(1),
    email: z.string().email(),
    password: z.string().min(8),
}).strict();                              // .strict() -> unknown keys rejected

const UpdateUser = z.object({
    displayName: z.string().min(1).optional(),
}).strict();

app.post('/api/users', async (req, res) => {
    const parsed = CreateUser.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid input' });

    const { username, email, password } = parsed.data;
    const user = new User({ username, email });
    await user.setPassword(password);
    user.role = 'user';                   // server-controlled fields set in code
    user.isVerified = false;
    user.balance = 0;
    await user.save();
    res.status(201).json({ id: user._id, username: user.username });
});

app.patch('/api/users/me', async (req, res) => {
    const parsed = UpdateUser.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid input' });

    const user = await User.findById(req.userId);
    if (parsed.data.displayName !== undefined) user.displayName = parsed.data.displayName;
    await user.save();
    res.json({ id: user._id, displayName: user.displayName });
});
```

**What changed**: a `zod` `.strict()` schema is the input boundary, so only whitelisted keys survive. The model is constructed field-by-field from validated data—never from `req.body` directly.

## Spring Boot + JPA (Java)

### Vulnerable
```java
// User is a JPA @Entity with: username, email, role, verified, balance
@RestController
class UserController {

    // Binding the request straight onto the @Entity: every matching field is set.
    @PostMapping("/api/users")
    public User create(@RequestBody User user) {   // {"role":"ADMIN"} is bound here
        return repository.save(user);
    }

    @PatchMapping("/api/users/me")
    public User update(@RequestBody User incoming, Principal principal) {
        User user = repository.findByUsername(principal.getName());
        user.setRole(incoming.getRole());          // whatever the client sent
        user.setVerified(incoming.isVerified());   // ...including sensitive fields
        user.setBalance(incoming.getBalance());
        return repository.save(user);
    }
}
```

**Why it's vulnerable**: `@RequestBody User` lets Jackson populate the entity from the JSON, so `role`, `verified`, and `balance` are all settable by the caller. The update copies them back verbatim.

### Secure
```java
// Input DTOs — only client-settable fields exist on these records.
public record UserCreateRequest(
        @NotBlank String username,
        @Email String email,
        @NotBlank String password) {}

public record UserUpdateRequest(String displayName) {}

@RestController
class UserController {

    @PostMapping("/api/users")
    public UserView create(@RequestBody @Valid UserCreateRequest req) {
        User user = new User();
        user.setUsername(req.username());
        user.setEmail(req.email());
        user.setPassword(encoder.encode(req.password()));
        user.setRole(Role.USER);            // server-controlled, never from request
        user.setVerified(false);
        user.setBalance(BigDecimal.ZERO);
        return UserView.from(repository.save(user));
    }

    @PatchMapping("/api/users/me")
    public UserView update(@RequestBody @Valid UserUpdateRequest req, Principal principal) {
        User user = repository.findByUsername(principal.getName());
        if (req.displayName() != null) user.setDisplayName(req.displayName());
        return UserView.from(repository.save(user));   // role/balance untouched
    }
}

// Defense in depth: block sensitive fields on the entity too.
@Entity
class User {
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Role role;                      // never bound from client JSON
    @JsonIgnore
    private BigDecimal balance;             // never (de)serialized to/from clients
    // ...
}
```

**What changed**: request binding targets a DTO record that has no sensitive fields, and mapping to the entity is explicit. `@JsonProperty(READ_ONLY)` and `@JsonIgnore` add a second layer so the entity itself refuses to bind those fields.

## What Changed, and Why

| Aspect | Vulnerable | Secure |
|--------|-----------|--------|
| Binding target | Persistence/domain model (`User`, entity, document) | Input DTO / schema with only client-settable fields |
| Field selection | All keys in the body (`**body`, `new Model(body)`, `@RequestBody Entity`) | Explicit allow-list; unknown keys rejected (`extra='forbid'`, `.strict()`, DTO record) |
| Sensitive fields | Client can set `role`, `isVerified`, `balance` | Server assigns them from trusted state; marked read-only / ignored |
| Update handler | Merges the whole body onto the record | Applies only whitelisted, validated fields |
| Result of `"role":"admin"` | Persisted → privilege escalation | Rejected or ignored → no effect |

## Next Steps

- **[Prevention](prevention.md)**: The full allow-list and two-model strategy
- **[Attack Vectors](attack-vectors.md)**: How these bindings are discovered and exploited
- **[API Security Top 10](/learn/api)**: Return to the full learning path
- **[Practice](/practice)**: Fix a vulnerable binding in a hands-on challenge
