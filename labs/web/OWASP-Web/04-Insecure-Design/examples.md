# Insecure Design - Examples

## Bad vs Good Code Comparisons

**❌ VULNERABLE**: No rate limiting
```python
@app.route("/login")
def login():
    # Unlimited attempts
```

**✅ SECURE**: Rate limiting
```python
@limiter.limit("5 per minute")
@app.route("/login")
```

## Key Takeaways

1. Design security from the start
2. Implement rate limiting
3. Validate business logic
4. Multiple security layers

## What's Next?

- **[Overview](./overview.md)**: Understand what insecure design is
- **[Attack Vectors](./attack-vectors.md)**: Learn how attacks happen
- **[Prevention](./prevention.md)**: Best practices for prevention
- **[Lab](./lab/)**: Hands-on practice

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
