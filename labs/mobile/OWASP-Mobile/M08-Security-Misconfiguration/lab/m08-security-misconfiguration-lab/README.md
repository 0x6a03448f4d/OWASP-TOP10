# M08: Security Misconfiguration - Lab

## Overview

This lab demonstrates common security misconfigurations in mobile applications and their backend services, including:
- Debug mode enabled in production
- Verbose error messages exposing internal details
- Development endpoints left accessible
- Sensitive data in logs and configuration
- Insecure default settings
- Unnecessary features and services enabled

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner to Intermediate

## Learning Objectives

By completing this lab, you will:
1. Identify common security misconfigurations in mobile apps
2. Understand how debug mode and verbose errors expose sensitive information
3. Learn the risks of leaving development features in production
4. Discover how misconfigurations lead to information disclosure
5. Implement proper security configurations

## Lab Setup

### Prerequisites
- Docker and Docker Compose installed
- Basic understanding of web applications and mobile APIs
- A web browser
- (Optional) Command-line tools like curl for API testing

### Starting the Lab

```bash
cd OWASP-Mobile/M08-Security-Misconfiguration/lab/m08-security-misconfiguration-lab/
docker-compose up
```

The application will be available at: `http://localhost:5108`

## What You'll Find

This lab includes:
- A simulated mobile application backend with Flask
- Multiple security misconfigurations to discover
- Interactive exercises demonstrating real-world vulnerabilities
- Examples of both vulnerable and secure configurations

### Misconfigurations Demonstrated

1. **Debug Mode in Production**: Flask application running with `debug=True`
2. **Verbose Error Messages**: Full stack traces and detailed error information exposed
3. **Configuration Exposure**: Database credentials and API keys in configuration endpoints
4. **Development Endpoints**: Debug and code execution endpoints accessible
5. **Excessive Logging**: Sensitive data logged and exposed through endpoints
6. **Information Disclosure**: Server status, health checks revealing too much
7. **Insecure Defaults**: Weak session settings, missing security headers

## Next Steps

Once the lab is running, follow the step-by-step instructions in [instructions.md](./instructions.md) to:
1. Explore the vulnerable implementation
2. Identify security misconfigurations
3. Understand the risks and attack scenarios
4. Learn how to fix each misconfiguration
5. Implement secure configuration practices

## Stopping the Lab

```bash
docker-compose down
```

## Security Note

⚠️ **IMPORTANT**: This lab intentionally contains severe security vulnerabilities for educational purposes. The patterns demonstrated here should **NEVER** be used in production applications. Always:

- Disable debug mode in production
- Use generic error messages
- Remove development endpoints before deployment
- Protect sensitive configuration data
- Implement proper logging practices
- Follow security hardening guides for your framework

---

*Part of OWASP Mobile Top 10 - Educational Repository*
