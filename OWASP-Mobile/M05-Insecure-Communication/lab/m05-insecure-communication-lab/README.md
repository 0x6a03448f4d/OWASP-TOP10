# M05: Insecure Communication - Lab

## Overview

This lab demonstrates insecure communication vulnerabilities in mobile applications, including:
- Unencrypted HTTP transmission of sensitive data
- Weak TLS configuration  
- Certificate validation bypass
- Man-in-the-Middle (MITM) attack scenarios

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner to Intermediate

## Learning Objectives

By completing this lab, you will:
1. Understand how data is exposed over unencrypted channels
2. Learn to intercept HTTP traffic using proxy tools
3. Identify weak TLS configurations
4. Practice implementing secure HTTPS communication
5. Understand certificate validation and pinning

## Lab Setup

### Prerequisites
- Docker and Docker Compose installed
- A network interception tool (optional):
  - Burp Suite Community Edition
  - mitmproxy
  - Charles Proxy
  - Wireshark
- Basic understanding of HTTP/HTTPS protocols

### Starting the Lab

```bash
cd OWASP-Mobile/M05-Insecure-Communication/lab/m05-insecure-communication-lab/
docker-compose up
```

The application will be available at:
- HTTP endpoint: `http://localhost:5200`
- HTTPS endpoint: `https://localhost:5201` (with self-signed certificate)

## What You'll Find

This lab includes:
- A vulnerable mobile API backend with HTTP endpoints
- Simulated mobile app making insecure network calls
- Examples of credential transmission over cleartext
- Weak TLS configuration demonstrations
- Tools to intercept and analyze traffic

## Vulnerability Scenarios

### 1. Cleartext HTTP Communication
The app transmits login credentials and user data over HTTP, making them visible to attackers on the network.

### 2. Mixed Content
Some resources load over HTTPS while others use HTTP, creating security gaps.

### 3. Disabled Certificate Validation
The app accepts self-signed and invalid certificates, enabling MITM attacks.

### 4. Sensitive Data Exposure
API keys, session tokens, and personal information transmitted without encryption.

## Next Steps

Once the lab is running, follow the step-by-step instructions in [instructions.md](./instructions.md) to:
1. Explore the vulnerable HTTP implementation
2. Intercept cleartext traffic
3. Capture credentials and tokens
4. Understand the attack impact
5. Implement secure HTTPS alternatives

## Stopping the Lab

```bash
docker-compose down
```

## Additional Resources

- [OWASP Mobile Top 10 - M05](https://owasp.org/www-project-mobile-top-10/)
- [OWASP Mobile Security Testing Guide](https://mobile-security.gitbook.io/)
- [TLS Best Practices](https://wiki.mozilla.org/Security/Server_Side_TLS)

---

*Part of OWASP Mobile Top 10 - Educational Repository*
