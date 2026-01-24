# Injection - Prevention

## Core Prevention Principles

1. **Use Parameterized Queries**: Never concatenate user input
2. **Input Validation**: Whitelist acceptable patterns
3. **Least Privilege**: Limit database permissions
4. **Escape Output**: Context-appropriate encoding

## Secure Coding Patterns

```python
# SECURE: Parameterized query
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
```

## Security Checklist

- [ ] Using parameterized queries
- [ ] Input validation implemented
- [ ] Database user has minimal permissions
- [ ] Regular security testing

## What's Next?

- **[Overview](./overview.md)**: Understand what injection is
- **[Attack Vectors](./attack-vectors.md)**: Learn how attacks happen
- **[Examples](./examples.md)**: See vulnerable vs secure code
- **[Lab](./lab/)**: Practice fixing vulnerabilities

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
