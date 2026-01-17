# API08: Security Misconfiguration - Overview

## What is Security Misconfiguration?

**Security Misconfiguration** occurs when security settings are undefined, implemented incorrectly, or left at insecure defaults. For APIs, this includes CORS misconfigurations, verbose error messages, missing security headers, debug mode in production, and default credentials.

APIs are complex systems with many configuration points—servers, frameworks, libraries, databases, and cloud services. Each misconfiguration can expose the API to attacks.

### Core Concept

```
Secure Configuration:
- CORS: specific origins only
- Errors: generic messages
- Headers: all security headers present
- Debug: OFF in production
- Defaults: changed

Misconfiguration:
- CORS: * (allow all)
- Errors: full stack traces
- Headers: missing/misconfigured
- Debug: ON with sensitive data
- Defaults: admin/admin still works
```

## Why Does This Matter?

### Business Impact
- **Data Exposure**: Stack traces reveal file paths, DB schemas, secrets
- **Unauthorized Access**: Default credentials allow full control
- **CORS Bypass**: Steal user data from browsers
- **Information Disclosure**: Debug endpoints expose internals

### Technical Impact
- **CORS Misconfiguration**: Allow any origin to make authenticated requests
- **Verbose Errors**: Stack traces, DB queries, file paths exposed
- **Missing Security Headers**: XSS, clickjacking, MIME sniffing
- **Debug Mode**: Sensitive data in responses, interactive debuggers
- **Default Credentials**: Admin access with default passwords

## Common Misconfigurations

### 1. Overly Permissive CORS

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
**Risk**: Any website can steal user data

### 2. Verbose Error Messages

```json
{
  "error": "Traceback (most recent call last):\n File 'app.py', line 42\n SQL: SELECT * FROM users WHERE id=1337\n Database: postgres://admin:pass123@db.internal.com/prod"
}
```
**Risk**: Exposes internal structure, credentials, queries

### 3. Missing Security Headers

Missing:
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`

### 4. Debug Mode in Production

```json
{
  "debug": true,
  "config": {
    "DB_PASSWORD": "prod_secret_123",
    "AWS_KEY": "AKIAIOSFODNN7EXAMPLE"
  }
}
```

### 5. Default Credentials

```
admin/admin
root/root
api/api
```

## Real-World Impact

**Capital One (2019)**: WAF misconfiguration led to $80M fine

**Elasticsearch Exposures (2018-2020)**: Default config exposed 2.5 billion records

**MongoDB Instances**: 26,000+ exposed due to default no-auth configuration

## Prevalence

- 65% of APIs have at least one security misconfiguration
- 42% use overly permissive CORS
- 38% expose verbose errors in production
- 28% have debug mode enabled
- 15% use default credentials

## Prevention

1. **Secure CORS**: Whitelist specific origins
2. **Generic errors**: Hide implementation details
3. **Security headers**: Implement all recommended headers
4. **Disable debug**: Turn off in production
5. **Change defaults**: Update all default passwords
6. **Configuration management**: Automated, version controlled
7. **Regular audits**: Scan for misconfigurations

## Next Steps
- [Attack Vectors](attack-vectors.md)
- [Prevention](prevention.md)
- [Examples](examples.md)
- [Lab](lab/api08-misconfig-lab/)
