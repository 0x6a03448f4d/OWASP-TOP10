# API03: Broken Object Property Level Authorization

## Overview

Broken Object Property Level Authorization occurs when APIs expose too many object properties or allow users to modify properties they shouldn't have access to. This vulnerability manifests in two primary forms:

1. **Excessive Data Exposure**: APIs return more data than necessary, exposing sensitive fields
2. **Mass Assignment**: APIs accept all properties in user input, allowing modification of restricted fields

## Documentation

### [📖 Overview](./overview.md)
Comprehensive introduction to API03 vulnerabilities:
- What is property-level authorization
- Mass assignment vs excessive data exposure
- Why it matters for modern APIs
- Real-world impact and case studies
- Common misunderstandings
- Statistics and prevalence

### [⚔️ Attack Vectors](./attack-vectors.md)
Detailed exploitation techniques:
- Excessive data exposure attacks
- Mass assignment for privilege escalation
- Financial fraud via property manipulation
- Data harvesting and enumeration
- Advanced attack scenarios
- Automated exploitation tools

### [🛡️ Prevention](./prevention.md)
Best practices and secure implementation:
- Data Transfer Objects (DTOs)
- Field-level authorization
- Role-based filtering
- Framework-specific implementations (Flask, FastAPI, Django, Express)
- Testing and validation strategies
- Complete security checklist

### [💻 Examples](./examples.md)
Code examples showing vulnerable vs secure patterns:
- User profile APIs (vulnerable and secure)
- E-commerce product management
- Order processing systems
- Banking APIs
- Multiple framework implementations
- Complete application examples

## Hands-On Lab

### [🔬 Mass Assignment Lab](./lab/api03-mass-assignment-lab/)

Interactive lab environment to practice exploiting and fixing property-level authorization vulnerabilities.

**What you'll learn:**
- Identify excessive data exposure in API responses
- Exploit mass assignment to gain admin privileges
- Harvest sensitive data from over-exposed endpoints
- Implement proper DTOs with Marshmallow
- Add field-level authorization controls
- Test security fixes

**Lab Features:**
- Vulnerable Flask API with realistic scenarios
- Pre-configured user accounts (regular users + admin)
- Docker-based deployment for easy setup
- Comprehensive step-by-step instructions
- Automated testing scripts
- 8+ hands-on exercises

**Quick Start:**
```bash
cd lab/api03-mass-assignment-lab/
docker-compose up -d
# API available at http://localhost:5003
```

## Key Concepts

### Excessive Data Exposure
```json
// ❌ VULNERABLE: Exposes sensitive fields
{
  "id": 123,
  "username": "alice",
  "email": "alice@example.com",
  "password_hash": "$2b$12$...",    // Should be hidden
  "is_admin": false,                 // Should be hidden
  "salary": 65000,                   // Should be hidden
  "api_key": "key_user_alice"        // Should be hidden
}

// ✅ SECURE: Only safe fields exposed
{
  "id": 123,
  "username": "alice",
  "email": "alice@example.com",
  "created_at": "2024-01-15"
}
```

### Mass Assignment
```python
# ❌ VULNERABLE: Accepts any field
@app.route('/api/users/<id>', methods=['PUT'])
def update_user(id):
    data = request.json
    for key, value in data.items():
        setattr(user, key, value)  # Dangerous!

# ✅ SECURE: Explicit allowlist
class UserUpdateSchema(Schema):
    username = fields.Str()
    email = fields.Email()
    # is_admin NOT in schema = cannot be modified
```

## Real-World Impact

- **GitHub (2020)**: Mass assignment in repository permissions API
- **E-commerce Platform**: Price manipulation via mass assignment ($999 → $0.01)
- **Healthcare API**: HIPAA violation from exposed patient data ($4.3M fine)
- **Social Media**: Mass data harvesting of private email addresses

## Learning Path

1. **Start with [Overview](./overview.md)** - Understand the vulnerability
2. **Read [Attack Vectors](./attack-vectors.md)** - Learn exploitation techniques
3. **Complete the [Lab](./lab/api03-mass-assignment-lab/)** - Practice hands-on
4. **Study [Prevention](./prevention.md)** - Implement secure patterns
5. **Review [Examples](./examples.md)** - See real code implementations

## Prerequisites

- Basic understanding of REST APIs
- Familiarity with HTTP requests and JSON
- Knowledge of at least one backend framework (Flask, FastAPI, Django, or Express)
- Understanding of authentication vs authorization

## Related Vulnerabilities

- **API01**: Broken Object Level Authorization (accessing entire objects)
- **API05**: Broken Function Level Authorization (accessing endpoints)
- **API08**: Security Misconfiguration (related to default serialization)

## Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [Marshmallow Documentation](https://marshmallow.readthedocs.io/)
- [Pydantic Documentation](https://docs.pydantic.dev/)

## Contributing

Found an issue or want to improve the documentation? Please contribute to the [OWASP-TOP10 repository](https://github.com/0x6a03448f4d/OWASP-TOP10).

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
