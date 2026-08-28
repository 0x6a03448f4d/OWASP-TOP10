# API3:2019 Excessive Data Exposure - Code Examples

Each pair below shows a **vulnerable** handler that serialises the whole model and the **secure** version that returns an explicit, allow-listed response. The scenario is the same throughout: a `User` record whose row contains sensitive fields (`password_hash`, `mfa_secret`, `is_admin`, `internal_risk_score`) that must never reach the client, while the app only needs `id`, `display_name`, and `avatar_url`.

## Flask + SQLAlchemy (Python)

### Vulnerable
```python
from flask import Flask, jsonify
from models import User

app = Flask(__name__)

@app.route('/api/users/<int:uid>')
def get_user(uid):
    user = User.query.get_or_404(uid)
    # to_dict() dumps EVERY column: password_hash, mfa_secret, is_admin,
    # internal_risk_score, stripe_customer_id, precise_lat/lng ... all leak.
    return jsonify(user.to_dict())

@app.route('/api/users')
def list_users():
    # Even worse: full objects for EVERY user in one response.
    return jsonify([u.to_dict() for u in User.query.all()])
```

### Secure
```python
from flask import Flask, jsonify, abort
from sqlalchemy.orm import load_only
from models import User, db

app = Flask(__name__)

# Explicit allow-list: only these fields can ever leave the server.
def user_public(user):
    return {
        'id': user.id,
        'displayName': user.display_name,
        'avatarUrl': user.avatar_url,
    }

@app.route('/api/users/<int:uid>')
def get_user(uid):
    user = (db.session.query(User)
            .options(load_only(User.id, User.display_name, User.avatar_url))
            .get(uid))            # sensitive columns are never even loaded
    if user is None:
        abort(404)
    return jsonify(user_public(user))

@app.route('/api/users')
def list_users():
    users = (db.session.query(User)
             .options(load_only(User.id, User.display_name, User.avatar_url))
             .all())
    return jsonify([user_public(u) for u in users])   # minimal objects only
```

## Django REST Framework (Python)

### Vulnerable
```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'      # deny-list mindset: exposes every column,
                                # including any sensitive field added later

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer   # /api/users returns full rows
```

### Secure
```python
class UserPublicSerializer(serializers.ModelSerializer):
    displayName = serializers.CharField(source='display_name')
    avatarUrl = serializers.CharField(source='avatar_url')
    class Meta:
        model = User
        fields = ['id', 'displayName', 'avatarUrl']   # explicit allow-list

class UserSelfSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'display_name', 'avatar_url', 'email', 'phone']
        # own contact info, but NEVER password_hash / mfa_secret / is_admin

class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.only('id', 'display_name', 'avatar_url')

    def get_serializer_class(self):
        obj_id = self.kwargs.get('pk')
        if obj_id and str(self.request.user.pk) == str(obj_id):
            return UserSelfSerializer          # self view: a few more fields
        return UserPublicSerializer            # everyone else: minimal
```

## Express (Node.js)

### Vulnerable
```javascript
const express = require('express');
const app = express();

app.get('/api/users/:id', async (req, res) => {
  const user = await db.users.findById(req.params.id);
  res.json(user);                 // whole document: passwordHash, mfaSecret,
                                  // isAdmin, internalRiskScore ... all sent
});

app.get('/api/users', async (req, res) => {
  const users = await db.users.find();
  res.json(users);                // full documents for everyone
});
```

### Secure
```javascript
const express = require('express');
const { z } = require('zod');
const app = express();

// Strict output contract: unknown keys are rejected, not silently passed.
const UserResponse = z.object({
  id: z.number(),
  displayName: z.string(),
  avatarUrl: z.string().url(),
}).strict();

function toUserDto(u) {
  return { id: u.id, displayName: u.displayName, avatarUrl: u.avatarUrl };
}

app.get('/api/users/:id', async (req, res, next) => {
  try {
    // Projection at the query layer: sensitive fields never loaded.
    const user = await db.users.findById(req.params.id,
      { projection: { id: 1, displayName: 1, avatarUrl: 1 } });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(UserResponse.parse(toUserDto(user)));   // validated on the way out
  } catch (e) { next(e); }
});

app.get('/api/users', async (req, res, next) => {
  try {
    const users = await db.users.find({},
      { projection: { id: 1, displayName: 1, avatarUrl: 1 } });
    res.json(users.map(u => UserResponse.parse(toUserDto(u))));
  } catch (e) { next(e); }
});
```

## Spring Boot (Java)

### Vulnerable
```java
@RestController
class UserController {
    @Autowired UserRepository repo;

    @GetMapping("/api/users/{id}")
    public User getUser(@PathVariable Long id) {
        // Returns the JPA entity directly. Jackson serialises every field,
        // including passwordHash, mfaSecret, admin, internalRiskScore.
        return repo.findById(id).orElseThrow();
    }

    @GetMapping("/api/users")
    public List<User> list() { return repo.findAll(); }   // full entities
}
```

### Secure
```java
// Explicit response record — a DTO, deliberately NOT the entity.
public record UserDto(Long id, String displayName, String avatarUrl) {
    public static UserDto from(User u) {
        return new UserDto(u.getId(), u.getDisplayName(), u.getAvatarUrl());
    }
}

@RestController
class UserController {
    @Autowired UserRepository repo;

    @GetMapping("/api/users/{id}")
    public UserDto getUser(@PathVariable Long id) {
        return UserDto.from(repo.findById(id).orElseThrow());  // only 3 fields
    }

    @GetMapping("/api/users")
    public List<UserDto> list() {
        return repo.findAll().stream().map(UserDto::from).toList();
    }
}
// Tip: a projection interface (id, displayName, avatarUrl) lets Spring Data
// fetch only those columns from the database as well.
```

## GraphQL (field-level authorization)

### Vulnerable
```graphql
type User {
  id: ID!
  displayName: String!
  email: String!          # returned to anyone who asks
  passwordHash: String!   # present on the type = an attacker can select it
  mfaSecret: String!
}
```

### Secure
```graphql
# Secrets are not in the schema at all; sensitive PII is field-authorized.
type User {
  id: ID!
  displayName: String!
  avatarUrl: String!
  email: String            # nullable; resolver enforces authorization
}
```
```javascript
// Resolver: only the user themself (or an admin) gets the email.
const resolvers = {
  User: {
    email: (user, _args, ctx) => {
      if (ctx.viewer.id !== user.id && !ctx.viewer.isAdmin)
        throw new ForbiddenError('not authorized for email');
      return user.email;
    },
  },
};
```

## What Changed, and Why

| Problem | Vulnerable | Secure |
|---------|-----------|--------|
| Field selection | Whole model / `__all__` / entity returned | Explicit DTO allow-list of named fields |
| Data loading | `SELECT *` / full document | Projection: only returned columns loaded |
| List endpoints | Full objects for every record | Same minimal DTO applied to each item |
| New fields | Leak by default (deny-list) | Withheld by default (allow-list) |
| Response contract | None — whatever serialises, ships | Strict schema, unknown keys rejected |
| GraphQL | Secrets on the type, client picks | Secrets off-schema; PII field-authorized |

## Next Steps

- **[Prevention](prevention.md)**: The full layered response-minimisation strategy
- **[Attack Vectors](attack-vectors.md)**: How these over-shared responses are discovered and read
- **[API Security Learning Path](/learn/api)**: Continue with the rest of the OWASP API Top 10
- **[Practice](/practice)**: Apply these fixes against practice targets
