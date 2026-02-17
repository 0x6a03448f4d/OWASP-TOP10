# OWASP Top 10 2017 - Web Application Security

## Overview

The OWASP Top 10 2017 represents the most critical web application security risks as identified by the Open Web Application Security Project in 2017. This version served as the industry standard for several years and introduced several important categories.

## The 2017 Top 10

### A1:2017 - Injection
Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.

**Key Changes:** Remained #1 from 2013

### A2:2017 - Broken Authentication  
Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens.

**Key Changes:** Moved up from #3 in 2013 (was "Broken Authentication and Session Management")

### A3:2017 - Sensitive Data Exposure
Many web applications and APIs do not properly protect sensitive data, such as financial, healthcare, and PII.

**Key Changes:** Combined several categories from 2013

### A4:2017 - XML External Entities (XXE)
Many older or poorly configured XML processors evaluate external entity references within XML documents.

**Key Changes:** **NEW** in 2017

### A5:2017 - Broken Access Control
Restrictions on what authenticated users are allowed to do are often not properly enforced.

**Key Changes:** Merged from two categories in 2013 (#4 and #7)

### A6:2017 - Security Misconfiguration
Security misconfiguration is the most commonly seen issue.

**Key Changes:** Remained #6 from 2013

### A7:2017 - Cross-Site Scripting (XSS)
XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping.

**Key Changes:** Moved down from #3 in 2013

### A8:2017 - Insecure Deserialization
Insecure deserialization often leads to remote code execution.

**Key Changes:** **NEW** in 2017

### A9:2017 - Using Components with Known Vulnerabilities  
Components run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.

**Key Changes:** Remained #9 from 2013

### A10:2017 - Insufficient Logging & Monitoring
Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response.

**Key Changes:** **NEW** in 2017

## Major Changes from 2013

**New Categories:**
- A4:2017-XML External Entities (XXE)
- A8:2017-Insecure Deserialization
- A10:2017-Insufficient Logging & Monitoring

**Removed Categories:**
- Unvalidated Redirects and Forwards (merged into other categories)
- Cross-Site Request Forgery (CSRF) (dropped from top 10)

## Resources

- [OWASP Top 10 2017 Official Release](https://owasp.org/www-project-top-ten/2017/)
- [OWASP Top 10 2017 PDF](https://github.com/OWASP/Top10/blob/master/2017/OWASP%20Top%2010-2017%20(en).pdf)

## Available Content

This platform provides:
- ✅ **Cheatsheets** - Quick reference guides for all 10 vulnerabilities
- ✅ **Quiz Questions** - Test your knowledge of 2017 vulnerabilities
- 📋 **Documentation** - Detailed overview, examples, and prevention guides
- 🎯 **Attack Flows** - Visual attack scenarios
- ⚖️ **Compliance Mappings** - Map to industry standards

---

**Note:** While OWASP 2017 is archived, understanding its evolution helps security professionals track how vulnerabilities have changed over time. Many systems still reference the 2017 framework.
