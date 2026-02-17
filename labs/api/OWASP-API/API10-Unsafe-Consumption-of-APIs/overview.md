# API10: Unsafe Consumption of APIs - Overview

## What is Unsafe Consumption of APIs?

**Unsafe Consumption of APIs** occurs when an API blindly trusts and processes data from third-party APIs without proper validation. Attackers can exploit this by compromising the third-party API or manipulating responses to inject malicious data.

### Core Concept

```
Safe Consumption:
✓ Validate all third-party data
✓ Sanitize inputs
✓ Don't trust response codes
✓ Implement timeouts
✓ Handle errors safely

Unsafe Consumption:
✗ Blindly trust third-party data
✗ No input validation
✗ Assume responses are safe
✗ No error handling
✗ Pass third-party data directly to DB/users
```

## Why Does This Matter?

### Business Impact
- **Data Injection**: Malicious data from APIs injected into your database
- **XSS Attacks**: User-facing data from third-party contains scripts
- **Business Logic Bypass**: Manipulated API responses alter behavior
- **Supply Chain Attacks**: Compromised partner APIs infect your system

### Technical Impact
- **SQL Injection**: Third-party data used in unparameterized queries
- **XSS**: Third-party HTML/JS rendered without sanitization
- **XXE**: Third-party XML parsed with external entities enabled
- **Command Injection**: Third-party data passed to system commands
- **Deserialization**: Untrusted data deserialized

## Common Scenarios

### 1. Payment API Consumption

```python
# VULNERABLE
@app.route('/process-payment', methods=['POST'])
def process_payment():
    # Call third-party payment API
    payment_response = requests.post('https://payment-api.com/charge', 
                                     json=request.json)
    
    # Blindly trust response
    if payment_response.json()['status'] == 'success':
        # Grant access - NO VALIDATION!
        give_access(request.json['user_id'])
```

**Attack**: Attacker intercepts/modifies payment API response

### 2. Weather API Data Display

```python
# VULNERABLE
weather_data = requests.get('https://weather-api.com/current').json()
# Display without sanitization - XSS risk!
return f"<div>Weather: {weather_data['description']}</div>"
```

**Attack**: If weather API compromised, can inject `<script>steal_cookies()</script>`

### 3. User Data Import

```python
# VULNERABLE
user_data = requests.get('https://crm-api.com/users').json()
for user in user_data['users']:
    # Direct insertion - SQL injection risk!
    db.execute(f"INSERT INTO users VALUES ('{user['name']}', '{user['email']}')")
```

**Attack**: CRM API returns malicious data like `'); DROP TABLE users;--`

### 4. Third-Party Content Aggregation

```python
# VULNERABLE  
articles = requests.get('https://news-api.com/articles').json()
# Render without sanitization
for article in articles['items']:
    render_template('article.html', content=article['html'])  # XSS!
```

## Real-World Impact

**British Airways (2018)**: Third-party script compromised, injected into BA site, 380K payment cards stolen, £20M fine

**Ticketmaster (2018)**: Third-party chatbot provider compromised, malware injected, 40K cards stolen

**Newegg (2018)**: Third-party payment service compromised, 14 months of credit card theft

## Prevalence

- 58% of APIs consume third-party services
- 71% don't validate third-party data adequately
- 45% pass third-party data directly to databases
- 39% render third-party HTML without sanitization
- 62% assume third-party APIs are always trustworthy

## Prevention

1. **Validate Everything**: Never trust third-party data
2. **Sanitize Inputs**: Treat as user input
3. **Verify Responses**: Check signatures, certificates
4. **Parameterized Queries**: Never concatenate third-party data into queries
5. **Output Encoding**: Sanitize before rendering
6. **Error Handling**: Don't expose third-party errors to users
7. **Monitoring**: Alert on unexpected third-party responses

## Next Steps
- [Attack Vectors](attack-vectors.md)
- [Prevention](prevention.md)
- [Examples](examples.md)
- [Lab](lab/api10-unsafe-consumption-lab/)
