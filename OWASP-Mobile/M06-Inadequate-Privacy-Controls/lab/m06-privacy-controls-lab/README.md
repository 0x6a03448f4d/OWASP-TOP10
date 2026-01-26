# M06: Inadequate Privacy Controls - Lab

## Overview

Welcome to the **Inadequate Privacy Controls** hands-on lab! This interactive environment demonstrates common privacy violations in mobile applications, including excessive permission requests, background data collection, PII leakage, and lack of user consent mechanisms.

**⚠️ Educational Purpose**: This lab contains intentional privacy vulnerabilities for learning. Never implement these patterns in production applications.

---

## Learning Objectives

By completing this lab, you will:

1. **Identify Privacy Violations**: Recognize excessive data collection, permission abuse, and PII leakage
2. **Understand Privacy Risks**: Learn how inadequate controls lead to user tracking and data exploitation
3. **Analyze Data Flows**: Trace how user data is collected, stored, and potentially shared
4. **Implement Privacy Controls**: Apply data minimization, consent mechanisms, and user transparency
5. **Test Privacy Compliance**: Use tools to detect privacy violations in applications

**Estimated Time**: 45-60 minutes  
**Difficulty**: Intermediate  
**Prerequisites**: Understanding of mobile development, HTTP requests, and privacy regulations (GDPR/CCPA helpful)

---

## Lab Setup

### Prerequisites

- **Docker** and **Docker Compose** installed
- **Web Browser** (Chrome, Firefox, or Safari)
- **Terminal** or command-line access
- **Network Analysis Tools** (optional): Browser DevTools, curl, or Postman

### Starting the Lab

1. **Navigate to the lab directory**:
   ```bash
   cd OWASP-Mobile/M06-Inadequate-Privacy-Controls/lab/m06-privacy-controls-lab
   ```

2. **Start the vulnerable application**:
   ```bash
   docker-compose up --build
   ```

3. **Access the application**:
   - Open your browser to: **http://localhost:5106**
   - You should see the "Privacy Controls Demo" interface

4. **Verify the lab is running**:
   ```bash
   curl http://localhost:5106/health
   # Expected: {"status": "healthy"}
   ```

---

## What You'll Find

This lab simulates a mobile application backend with multiple privacy violations:

### 1. **Permission Request Simulator**
- Demonstrates excessive permission requests
- Shows forced consent patterns
- Illustrates permission bundling abuse

### 2. **Background Data Collection**
- Simulates continuous location tracking
- Shows data collection without user awareness
- Demonstrates battery and privacy impact

### 3. **PII Leakage Scenarios**
- Logs containing personally identifiable information
- Analytics events with sensitive data
- Crash reports exposing user details

### 4. **Contact Harvesting**
- Demonstrates mass contact collection
- Shows third-party data sharing
- Illustrates consent violations

### 5. **Privacy Violation Detector**
- Tools to identify data leakage
- Network traffic analysis
- Compliance checking

---

## Key Vulnerabilities

This lab demonstrates the following privacy control issues:

| Vulnerability | OWASP Mobile Top 10 | Severity |
|---------------|---------------------|----------|
| Excessive permission requests | M06 | High |
| Background location tracking | M06 | Critical |
| PII in application logs | M06 | High |
| Contact list harvesting | M06 | Critical |
| Lack of user consent | M06 | High |
| Analytics PII exposure | M06 | Medium |
| Third-party SDK data sharing | M06 | High |
| No data deletion capability | M06 | Medium |

---

## Getting Started

1. **Start with the Overview Page**: Familiarize yourself with the demonstration scenarios
2. **Follow the Instructions**: Open `instructions.md` for step-by-step exercises
3. **Use Browser DevTools**: Monitor network requests to see data being sent
4. **Take Notes**: Document privacy violations you discover
5. **Think Like an Attacker**: Consider how collected data could be exploited

---

## Lab Architecture

```
┌─────────────────┐
│   Web Browser   │
│  localhost:5106 │
└────────┬────────┘
         │ HTTP
         ↓
┌─────────────────────────────┐
│   Flask Application         │
│   (Vulnerable Backend)      │
│                             │
│   Endpoints:                │
│   - /permissions            │
│   - /track-location         │
│   - /collect-data           │
│   - /harvest-contacts       │
│   - /analytics              │
└─────────────────────────────┘
```

---

## Next Steps

1. **Read the Instructions**: Open [instructions.md](instructions.md) for guided exercises
2. **Explore the Application**: Interact with each demonstration scenario
3. **Analyze Network Traffic**: Use browser DevTools to inspect requests
4. **Identify Violations**: Document privacy issues you find
5. **Propose Solutions**: Think about how to fix each vulnerability

---

## Stopping the Lab

When you're finished:

```bash
# Stop the containers
docker-compose down

# Remove containers and volumes (optional)
docker-compose down -v
```

---

## Privacy Compliance Context

This lab helps you understand regulations like:

- **GDPR** (General Data Protection Regulation): EU privacy law requiring consent, data minimization, and user rights
- **CCPA** (California Consumer Privacy Act): California law granting users data access and deletion rights
- **COPPA** (Children's Online Privacy Protection Act): US law protecting children's online privacy
- **App Store Guidelines**: Apple and Google privacy requirements for app approval

---

## Educational Disclaimer

⚠️ **Important**: This lab contains intentionally vulnerable code for educational purposes only. The privacy violations demonstrated here represent real-world anti-patterns that should **NEVER** be implemented in production applications.

**Key Points**:
- All data collection shown is excessive and violates privacy best practices
- Permission patterns demonstrated are considered dark patterns
- No actual user data is collected (this is a simulation)
- Real applications implementing these patterns face regulatory fines and user backlash

---

## Additional Resources

- **Module Documentation**: See [overview.md](../../overview.md), [attack-vectors.md](../../attack-vectors.md), and [prevention.md](../../prevention.md)
- **OWASP Mobile Security**: [Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- **Privacy Guidelines**: [Apple Privacy](https://developer.apple.com/privacy/), [Android Privacy](https://developer.android.com/privacy)

---

## Support

If you encounter issues:

1. **Check Docker is running**: `docker --version`
2. **Verify port 5106 is available**: `lsof -i :5106` (Unix/Mac) or `netstat -an | find "5106"` (Windows)
3. **View application logs**: `docker-compose logs -f`
4. **Restart the lab**: `docker-compose down && docker-compose up --build`

---

**Ready to begin?** Open [instructions.md](instructions.md) and start discovering privacy violations!

---

**Remember**: Privacy is not optional—it's a fundamental user right. Learn to recognize these violations so you can build privacy-respecting applications.
