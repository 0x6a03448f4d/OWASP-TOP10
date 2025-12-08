# Injection - Examples

## Bad vs Good Code Comparisons

**❌ VULNERABLE**:
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**✅ SECURE**:
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

## Key Takeaways

1. Never concatenate user input into queries
2. Use parameterized queries always
3. Validate input format
4. Apply least privilege

## What's Next?

- **[Overview](./overview.md)**: Understand what injection is
- **[Attack Vectors](./attack-vectors.md)**: Learn how attacks happen
- **[Prevention](./prevention.md)**: Best practices for prevention
- **[Lab](./lab/)**: Hands-on practice

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
