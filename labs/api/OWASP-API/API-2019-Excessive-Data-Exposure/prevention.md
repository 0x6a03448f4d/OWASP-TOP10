# API3:2019 Excessive Data Exposure - Prevention

## Prevention Strategy Overview

The cure for Excessive Data Exposure is a single principle applied everywhere: **the server decides exactly which fields leave, and it decides with an allow-list**. Never rely on the client to hide anything, and never serialise a whole model and hope the sensitive parts are ignored. Everything below is an implementation of that idea at a different layer:

1. Define explicit response DTOs/schemas per endpoint (allow-list the fields that ship).
2. Shape responses per consumer and per role, so privileged fields go only to privileged callers.
3. Stop auto-serialising full ORM models; select only the columns you return.
4. Validate outgoing responses against a schema so new fields fail closed.
5. Classify sensitive data and review responses continuously.

### Core Principles

- **Filter on the server, always**: the client is a display, not a security boundary.
- **Allow-list, never deny-list**: name the fields that may leave; everything unnamed is withheld by default.
- **Data minimisation**: return the least each consumer needs to do its job—nothing "just in case."
- **Least astonishment for new fields**: adding a column to a model must never silently add it to a response.

## 1. Explicit Response DTOs / Schemas (Allow-List)

Define a dedicated output type for each endpoint that lists precisely the fields the client receives. The model and the response are deliberately different objects.

```python
# Django REST Framework: allow-list fields explicitly (never __all__)
class UserPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'display_name', 'avatar_url']   # ONLY these leave
        # password_hash, mfa_secret, is_admin, etc. cannot appear because
        # they are not named. Adding a new column changes nothing here.
```

```typescript
// Node/TypeScript: map the entity to an explicit DTO
interface UserDto { id: number; displayName: string; avatarUrl: string; }

function toUserDto(u: UserEntity): UserDto {
  return { id: u.id, displayName: u.displayName, avatarUrl: u.avatarUrl };
  // No spread of the entity. Only listed fields exist on the DTO.
}
```

> **Anti-pattern to ban in review:** `return {...entity}`, `jsonify(model.__dict__)`, `fields = '__all__'`, and returning ORM objects directly. Each re-introduces the whole model.

## 2. Schema-Based Response Validation

Do not just *build* a safe response—*enforce* it. Validate every outgoing body against a strict schema that forbids unknown properties, so a stray field is dropped or the response fails loudly in tests.

```javascript
// Express + Zod: strict output schema strips/blocks extra keys
import { z } from 'zod';

const UserResponse = z.object({
  id: z.number(),
  displayName: z.string(),
  avatarUrl: z.string().url(),
}).strict();                       // .strict() rejects unknown keys

app.get('/api/users/:id', async (req, res) => {
  const user = await getUser(req.params.id);
  const body = UserResponse.parse(toUserDto(user));  // throws if extra fields sneak in
  res.json(body);
});
```

```yaml
# OpenAPI: mark the response schema closed so contract tests catch leaks
components:
  schemas:
    UserResponse:
      type: object
      additionalProperties: false      # no field may appear that isn't declared
      required: [id, displayName, avatarUrl]
      properties:
        id: { type: integer }
        displayName: { type: string }
        avatarUrl: { type: string, format: uri }
```

Wire `additionalProperties: false` into contract tests (e.g. Dredd, Schemathesis, or a response-validation middleware) so a new sensitive field breaks CI instead of leaking to production.

## 3. Per-Role / Per-Consumer Response Shaping

The same object often needs different shapes for different callers. Choose the serializer from the caller's role or client, on the server.

```python
# Choose the output contract by role — server-side decision
def serialize_user(user, requester):
    if requester.is_admin:
        return AdminUserSerializer(user).data   # e.g. adds status, flags (still explicit)
    if requester.id == user.id:
        return SelfUserSerializer(user).data     # own email/phone, never hash/secret
    return PublicUserSerializer(user).data       # display_name, avatar only
```

Notice that even the admin and "self" views are explicit allow-lists—more fields, but still enumerated. Secrets (hashes, MFA seeds) appear in *none* of them.

## 4. Select Only What You Return at the Data Layer

Stop the problem upstream: don't fetch columns you won't return. This also narrows the blast radius if a serializer is ever careless.

```sql
-- Project explicitly; avoid SELECT *
SELECT id, display_name, avatar_url FROM users WHERE id = $1;
```

```python
# SQLAlchemy: load only the columns you expose
from sqlalchemy.orm import load_only

user = (session.query(User)
        .options(load_only(User.id, User.display_name, User.avatar_url))
        .get(uid))
```

```javascript
// Prisma: `select` is an allow-list at the query level
const user = await prisma.user.findUnique({
  where: { id },
  select: { id: true, displayName: true, avatarUrl: true },  // hash/secret never loaded
});
```

## 5. Protect Nested and Related Objects

Nested objects need their *own* allow-list; never embed a raw related entity.

```typescript
// Order response embeds a MINIMAL customer, not the full user
interface OrderDto {
  id: number;
  total: number;
  customer: { id: number; displayName: string };   // no email/hash/notes
  payment:  { cardLast4: string };                  // no token/PAN/gatewayId
}
```

Apply the same DTO mapping recursively, and make eager-loaded relations pass through their own serializer rather than being spread wholesale.

## 6. Coarsen Sensitive Values on the Server

If the product only needs an approximate value, compute the approximation server-side and send *only* that. Never send the precise value and round it in the UI.

```python
# Send coarse distance, never raw coordinates
def public_location(user, viewer):
    miles = round(haversine(viewer.coords, user.coords))   # computed server-side
    return { "approxDistanceMiles": miles }                # lat/lng never serialized

# Mask on the server, transmit only the mask
def card_view(card):
    return { "last4": card.pan[-4:] }                      # full PAN stays server-side
```

## 7. Classify Data and Fail Closed

Tag sensitive fields at the model level so serialization can refuse them by default, turning "forgot to hide it" into "impossible to expose accidentally."

```python
# Mark sensitive attributes; a base serializer drops them unless explicitly opted in
SENSITIVE_FIELDS = {'password_hash', 'mfa_secret', 'reset_token',
                    'internal_risk_score', 'is_admin', 'tenant_id'}

def safe_dump(model, allow):
    data = model.to_dict()
    # allow-list intersect, then hard-strip anything sensitive as a backstop
    return {k: v for k, v in data.items()
            if k in allow and k not in SENSITIVE_FIELDS}
```

The allow-list is the primary control; the sensitive-field strip is a defence-in-depth backstop so a mistaken allow-list still can't leak a secret.

## 8. GraphQL: Field-Level Authorization

In GraphQL the client picks fields, so authorization must live on the field—never assume clients won't ask.

```javascript
const resolvers = {
  User: {
    email: (user, _args, ctx) => {
      if (ctx.viewer.id !== user.id && !ctx.viewer.isAdmin)
        throw new ForbiddenError('not authorized for email');
      return user.email;
    },
    passwordHash: () => { throw new ForbiddenError('never exposed'); },
  },
};
```

Also disable introspection in production where appropriate, and keep truly-secret fields out of the schema entirely rather than relying on a resolver guard alone.

## 9. Testing and Detection

Make over-exposure something CI catches, not something a researcher reports.

```python
# Contract test: the response must contain EXACTLY the allowed keys
def test_user_response_is_minimal(client):
    body = client.get('/api/users/42').json()
    assert set(body.keys()) == {'id', 'displayName', 'avatarUrl'}
    for forbidden in ('passwordHash', 'mfaSecret', 'isAdmin', 'email', 'phone'):
        assert forbidden not in body
```

```bash
# Grep-style guardrail in review/CI: flag whole-model serialization
grep -RnE "fields *= *'__all__'|jsonify\(.*\.__dict__|return \{\.\.\.(entity|user|model)\}" ./src
```

Complement automated checks with a manual response review during design and pen-test: read the raw JSON for every endpoint and confirm each field has a reason to be there.

## Summary of Layered Defences

| Layer | Control | Effect |
|-------|---------|--------|
| Data access | `SELECT`/`select` only returned columns | Sensitive columns never loaded |
| Serialization | Explicit DTO / allow-list fields | Only named fields can leave |
| Authorization | Per-role / per-field shaping | Privileged fields to privileged callers only |
| Contract | Schema with `additionalProperties: false` | Unknown fields fail closed |
| Verification | Contract tests + manual response review | Leaks caught in CI, not production |

## Key Takeaways

1. **Server-side allow-list, every time**—name the fields that ship; withhold everything else by default.
2. **DTOs are not the model**—map entities to explicit response objects; never spread or auto-dump the model.
3. **Validate the response contract**—`additionalProperties: false` and strict schemas make new fields fail closed.
4. **Shape by role and consumer**—different callers get different, still-explicit, views; secrets go to none.
5. **Test the bytes**—assert exact response keys and grep for whole-model serialization in CI.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure responses across frameworks
- **[Attack Vectors](attack-vectors.md)**: Understand exactly what you're defending against
- **[API Security Learning Path](/learn/api)**: Continue with the rest of the OWASP API Top 10
- **[Practice](/practice)**: Apply these defences against practice targets
