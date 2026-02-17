# API10: Unsafe API Consumption Lab

## Setup
```bash
docker-compose up -d
```
Access: http://localhost:5010

## Exercises

### Exercise 1: XSS via Weather API
See how third-party data with `<script>` tags executes in browser.

### Exercise 2: SQL Injection Risk
Observe malicious SQL in "imported" data from CRM API.

### Exercise 3: Payment Manipulation
Understand risk of trusting payment API responses.

### Exercise 4: Implement Safeguards
1. Sanitize all third-party data (escape HTML)
2. Validate data structure and types
3. Use parameterized queries
4. Verify payment signatures

## Success Criteria
- ✅ Demonstrate XSS from third-party
- ✅ Identify SQL injection payload
- ✅ Understand payment trust issues
- ✅ Implement proper validation
