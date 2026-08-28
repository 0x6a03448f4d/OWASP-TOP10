# API6:2019 Mass Assignment - Prevention

## Prevention Strategy Overview

Every effective defense against Mass Assignment comes down to a single principle: **the client may set only the fields you explicitly allow it to set**. Everything else—authorization, verification, financial, identity, and audit fields—is set by the server, from the server's own trusted state. Concretely:

1. Never bind the raw request body to a persistence/domain model.
2. Define an explicit, per-endpoint allow-list of bindable fields (a DTO or schema).
3. Mark server-controlled fields read-only / excluded so they can never be bound.
4. Separate input models from domain models so the two cannot drift into each other.
5. Validate and authorize per endpoint—create and update usually need different allow-lists.

### Core Principles

- **Allow-list, never blocklist**: enumerate what is permitted. A blocklist forgets the field you add next month; an allow-list is safe by construction.
- **Two models, not one**: the shape you accept from clients (input DTO) is not the shape you persist (domain model). Map deliberately between them.
- **Server owns sensitive state**: `role`, `balance`, `isVerified`, ownership, and timestamps are assigned in code from the session—never copied from the body.
- **Fail closed**: an unknown or disallowed field is ignored or rejected, never silently bound.

## 1. Explicit Allow-List of Bindable Fields

The most direct fix: pick the exact keys you accept and ignore the rest.

```python
# Python — build the model from an allow-list, not from **body
ALLOWED_CREATE = ("username", "email", "password")

def create_user(body):
    data = {k: body[k] for k in ALLOWED_CREATE if k in body}
    user = User(**data)               # role/isVerified/balance can't be bound
    user.role = "user"                # server sets sensitive fields itself
    user.is_verified = False
    db.session.add(user); db.session.commit()
    return user
```

Create and update frequently need *different* allow-lists—a field you accept on create (e.g. `email`) may be immutable on update, and vice versa.

## 2. Use DTOs / Schemas as the Input Boundary

Let a schema library define and enforce the allowed shape, so binding is validated and constrained in one place.

```python
# Python — Pydantic input model: only these fields exist, extras rejected
from pydantic import BaseModel, EmailStr, ConfigDict

class UserCreateDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")   # unknown keys -> validation error
    username: str
    email: EmailStr
    password: str

def create_user(payload: dict):
    dto = UserCreateDTO(**payload)     # "role" in payload -> rejected here
    user = User(username=dto.username, email=dto.email)
    user.set_password(dto.password)
    user.role = "user"                 # assigned by the server
    return save(user)
```

Setting `extra="forbid"` (or the framework's equivalent) turns an injected field into an explicit error rather than a silent bind—fail loudly.

## 3. Django REST Framework: Never Use `__all__`

The most common DRF mistake is `fields = "__all__"`, which makes every model field writable.

```python
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # Enumerate fields explicitly — never "__all__"
        fields = ["id", "username", "email"]
        read_only_fields = ["id"]      # server-owned fields are read-only

# role, is_staff, is_superuser, balance are simply absent from the serializer,
# so they can never be set by a request.
```

## 4. Rails Strong Parameters / Laravel Fillable

The frameworks that made "mass assignment" famous now ship safe patterns—use them.

```ruby
# Rails — strong parameters: permit exactly what the client may set
def user_params
  params.require(:user).permit(:username, :email, :password)
  # :role and :admin are NOT permitted, so they are stripped
end

User.new(user_params)
```

```php
// Laravel — allow-list with $fillable (and never set $guarded = [])
class User extends Model {
    protected $fillable = ['username', 'email', 'password'];
    // role, balance, is_verified are guarded by omission
}
User::create($request->only(['username', 'email', 'password']));
```

## 5. Spring: Bind to a DTO, Not to the Entity

Never let request binding touch a JPA `@Entity` directly. Bind to a request record/DTO and map fields yourself.

```java
// Input DTO — only client-settable fields exist here
public record UserCreateRequest(String username, String email, String password) {}

@PostMapping("/api/users")
public UserView create(@RequestBody @Valid UserCreateRequest req) {
    User user = new User();
    user.setUsername(req.username());
    user.setEmail(req.email());
    user.setPassword(encoder.encode(req.password()));
    user.setRole(Role.USER);         // server-controlled, never from the request
    return UserView.from(repo.save(user));
}
```

If you must expose an entity to binding, mark server-owned fields so they cannot be written:

```java
@Entity
public class User {
    @JsonIgnore                       // never (de)serialized from/to clients
    private Role role;

    // Or, to allow read but block write on the way in:
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private boolean isVerified;
}
```

You can also restrict Spring's field binder explicitly with `@InitBinder` and `setAllowedFields(...)`, but a dedicated DTO is the cleaner, harder-to-get-wrong option.

## 6. Mark Server-Controlled Fields Read-Only

Independently of the input model, defend at the object layer so a sensitive field cannot be bound even if an endpoint is careless.

| Stack | Read-only / exclude mechanism |
|-------|-------------------------------|
| Django REST Framework | `read_only_fields`, or `read_only=True` on the field |
| Pydantic / FastAPI | Separate input vs. output models; `extra="forbid"` |
| Jackson / Spring | `@JsonIgnore`, `@JsonProperty(access = READ_ONLY)` |
| Mongoose | `select: false` / omit from the update allow-list; `immutable: true` |
| Rails / Laravel | `attr_readonly` / omit from `permit` / `$fillable` |

## 7. Handle Nested and Ownership Fields Explicitly

Deep binding is where allow-lists are most often forgotten. Flatten the input and take relationships from trusted state.

```python
# Never bind nested identity/ownership from the body
# BAD:  order.customer_id = body["customer"]["id"]
# GOOD: ownership comes from the authenticated session
order.customer_id = current_user.id          # not from the request
order.status      = "pending"                # server sets initial state

# For genuine nested input, validate each nested DTO with its own allow-list.
```

Rule of thumb: **identity, ownership, and tenancy always come from the session/context, never from the request body.**

## 8. Separate Input Models from Domain Models

Make the two-model rule structural, so no one can accidentally bind a request onto a persistence object.

```
Request  -->  CreateUserDTO   (only client-settable fields, validated)
                  |
                  v  explicit mapping in code
              User (domain/persistence)   (role, balance set by server)
                  |
                  v  explicit mapping in code
Response <--  UserView DTO     (only client-visible fields)
```

This also closes the read-side mirror (Excessive Data Exposure): a dedicated output DTO returns only intended fields, so read endpoints stop teaching attackers your internal field names.

## 9. Testing and Detection

Prove the allow-list holds by attacking your own endpoints in CI.

```python
# Negative test: an injected sensitive field must NOT be bound
def test_register_ignores_role():
    r = client.post("/api/register", json={
        "username": "t", "email": "t@x.com", "password": "pw",
        "role": "admin", "isVerified": True, "balance": 9999,
    })
    assert r.status_code in (201, 400)
    created = get_user("t")
    assert created.role == "user"        # server default, not "admin"
    assert created.is_verified is False
    assert created.balance == 0
```

Add one such test per create/update endpoint, and consider a lint/CI check that flags direct binding patterns (`Model(**body)`, `new Model(req.body)`, `fields = "__all__"`, `$guarded = []`).

## 10. Monitoring

Watch for the signature of Mass Assignment probing: requests carrying fields the endpoint's schema does not define.

```python
# If the input DTO rejects unknown keys, log the rejection as a signal
SENSITIVE_KEYS = ("role", "is_admin", "is_staff", "isVerified",
                  "balance", "user_id", "owner_id", "status")

def flag_extra_fields(endpoint, body, src_ip):
    hits = [k for k in body if k in SENSITIVE_KEYS and k not in allowed(endpoint)]
    if hits:
        log.warning("mass-assignment probe endpoint=%s fields=%s src=%s",
                    endpoint, hits, src_ip)
```

## Prevention Checklist

- [ ] No endpoint binds the raw body to a persistence/domain model.
- [ ] Every create and update endpoint has an explicit allow-list (DTO/schema/`permit`/`fillable`).
- [ ] Unknown fields are rejected or ignored (`extra="forbid"`, no `__all__`, no `$guarded = []`).
- [ ] Authorization, verification, financial, identity, and audit fields are read-only / server-set.
- [ ] Ownership/tenancy is taken from the session, never the request body.
- [ ] Nested objects are validated with their own allow-lists.
- [ ] Negative tests assert injected sensitive fields are not bound.

## Key Takeaways

1. **Allow-list, never blocklist** — enumerate the fields a client may set; ignore or reject everything else.
2. **Two models, not one** — separate the input DTO from the domain model and map between them deliberately.
3. **The server owns sensitive fields** — role, balance, verification, ownership, and timestamps are set in code, from trusted state.
4. **Use the framework's safe pattern** — strong parameters, `fillable`, DRF explicit fields, Pydantic `extra="forbid"`, Spring DTOs.
5. **Test the boundary** — a negative test per endpoint proves that `"role":"admin"` goes nowhere.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure binding in Flask, Express, and Spring
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[API Security Top 10](/learn/api)**: Return to the full learning path
- **[Practice](/practice)**: Apply these defenses in hands-on challenges
