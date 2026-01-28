#!/usr/bin/env python3
"""
OWASP Year Content Generator
Generates cheatsheets, documentation, quizzes, and other content for OWASP 2017 and 2025
"""

import json
import os
from pathlib import Path

# OWASP Top 10 Data for each year
OWASP_DATA = {
    "2017": {
        "web": [
            {
                "number": 1,
                "id": "A1",
                "name": "Injection",
                "slug": "injection",
                "risk": "CRITICAL RISK",
                "description": "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.",
                "stats": {"rank": "#1", "apps_tested": "8%", "occurrences": "274K"},
                "exploits": [
                    "SQL Injection: Manipulate database queries",
                    "OS Command Injection: Execute system commands",
                    "LDAP Injection: Manipulate directory services queries",
                    "XPath Injection: Manipulate XML data queries",
                    "NoSQL Injection: Exploit NoSQL databases"
                ],
                "attack_flow": [
                    "Attacker identifies input field",
                    "Submits malicious input with special characters",
                    "Application fails to validate/sanitize input",
                    "Malicious code executed by interpreter",
                    "BREACH: Data exfiltration or system compromise!"
                ],
                "prevention": [
                    "Use parameterized queries (prepared statements)",
                    "Use Object Relational Mapping (ORM) frameworks",
                    "Validate and sanitize all user input",
                    "Apply whitelist input validation",
                    "Use LIMIT and other SQL controls to prevent mass disclosure"
                ]
            },
            {
                "number": 2,
                "id": "A2",
                "name": "Broken Authentication",
                "slug": "broken-authentication",
                "risk": "HIGH RISK",
                "description": "Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens.",
                "stats": {"rank": "#2", "apps_tested": "3%", "occurrences": "123K"},
                "exploits": [
                    "Credential Stuffing: Use lists of known passwords",
                    "Session Fixation: Force known session ID on victim",
                    "Brute Force: Automated password guessing",
                    "Session Hijacking: Steal or predict session tokens",
                    "Weak Password Recovery: Exploit password reset flaws"
                ],
                "attack_flow": [
                    "Attacker discovers weak authentication",
                    "Attempts credential stuffing or brute force",
                    "Application lacks rate limiting",
                    "Credentials compromised or session stolen",
                    "BREACH: Account takeover achieved!"
                ],
                "prevention": [
                    "Implement multi-factor authentication (MFA)",
                    "Use strong session management",
                    "Implement rate limiting and account lockout",
                    "Use secure password hashing (bcrypt, Argon2)",
                    "Prevent credential stuffing with CAPTCHA"
                ]
            },
            {
                "number": 3,
                "id": "A3",
                "name": "Sensitive Data Exposure",
                "slug": "sensitive-data-exposure",
                "risk": "HIGH RISK",
                "description": "Many web applications and APIs do not properly protect sensitive data, such as financial, healthcare, and PII, enabling attackers to steal or modify such data.",
                "stats": {"rank": "#3", "apps_tested": "4%", "occurrences": "125K"},
                "exploits": [
                    "Man-in-the-Middle: Intercept unencrypted data",
                    "Database Theft: Extract unencrypted database",
                    "Weak Encryption: Break weak algorithms",
                    "Missing HTTPS: Capture data in transit",
                    "Backup Exposure: Access unprotected backups"
                ],
                "attack_flow": [
                    "Attacker intercepts network traffic",
                    "Identifies unencrypted sensitive data",
                    "Captures credentials or personal information",
                    "Exploits weak or missing encryption",
                    "BREACH: Sensitive data stolen!"
                ],
                "prevention": [
                    "Encrypt all sensitive data at rest and in transit",
                    "Use TLS 1.2+ for all connections",
                    "Implement proper key management",
                    "Disable caching for sensitive data",
                    "Use strong encryption algorithms (AES-256)"
                ]
            },
            {
                "number": 4,
                "id": "A4",
                "name": "XML External Entities (XXE)",
                "slug": "xml-external-entities",
                "risk": "HIGH RISK",
                "description": "Many older or poorly configured XML processors evaluate external entity references within XML documents, leading to disclosure of internal files, port scanning, remote code execution, and denial of service attacks.",
                "stats": {"rank": "#4", "apps_tested": "2%", "occurrences": "47K"},
                "exploits": [
                    "File Disclosure: Read local system files",
                    "SSRF: Scan internal network ports",
                    "Denial of Service: Billion laughs attack",
                    "Remote Code Execution: Execute malicious code",
                    "Data Exfiltration: Steal sensitive information"
                ],
                "attack_flow": [
                    "Attacker uploads malicious XML file",
                    "XML parser processes external entities",
                    "External entity references local files",
                    "Parser returns file contents to attacker",
                    "BREACH: Internal files exposed!"
                ],
                "prevention": [
                    "Disable external entity processing in XML parsers",
                    "Use less complex data formats like JSON",
                    "Update XML processors and libraries",
                    "Implement whitelist server-side input validation",
                    "Use SAST tools to detect XXE vulnerabilities"
                ]
            },
            {
                "number": 5,
                "id": "A5",
                "name": "Broken Access Control",
                "slug": "broken-access-control",
                "risk": "CRITICAL RISK",
                "description": "Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data.",
                "stats": {"rank": "#5", "apps_tested": "5%", "occurrences": "144K"},
                "exploits": [
                    "Direct Object Reference: Access other users' data",
                    "Forced Browsing: Access restricted pages",
                    "Missing Function Level Access Control: Call admin APIs",
                    "Parameter Tampering: Modify authorization parameters",
                    "Elevation of Privilege: Gain higher access level"
                ],
                "attack_flow": [
                    "Attacker logs in as regular user",
                    "Discovers admin functionality in HTML source",
                    "Directly accesses admin endpoints",
                    "Server fails to verify authorization",
                    "BREACH: Admin access granted!"
                ],
                "prevention": [
                    "Deny by default, except for public resources",
                    "Implement server-side access control checks",
                    "Use centralized authorization mechanism",
                    "Log access control failures and alert admins",
                    "Invalidate JWT tokens on server after logout"
                ]
            },
            {
                "number": 6,
                "id": "A6",
                "name": "Security Misconfiguration",
                "slug": "security-misconfiguration",
                "risk": "HIGH RISK",
                "description": "Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.",
                "stats": {"rank": "#6", "apps_tested": "9%", "occurrences": "215K"},
                "exploits": [
                    "Default Credentials: Use factory passwords",
                    "Directory Listing: Browse server directories",
                    "Verbose Errors: Extract system information",
                    "Unnecessary Features: Exploit unused services",
                    "Missing Security Headers: Launch attacks"
                ],
                "attack_flow": [
                    "Attacker scans for common misconfigurations",
                    "Finds default admin credentials or open ports",
                    "Accesses administrative interface",
                    "Exploits misconfigured services",
                    "BREACH: System compromised!"
                ],
                "prevention": [
                    "Implement secure installation processes",
                    "Remove or disable unused features and frameworks",
                    "Review and update configurations regularly",
                    "Implement security headers (CSP, HSTS, etc.)",
                    "Use automated configuration scanning tools"
                ]
            },
            {
                "number": 7,
                "id": "A7",
                "name": "Cross-Site Scripting (XSS)",
                "slug": "cross-site-scripting",
                "risk": "CRITICAL RISK",
                "description": "XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping, or updates an existing web page with user-supplied data using a browser API that can create HTML or JavaScript.",
                "stats": {"rank": "#7", "apps_tested": "7%", "occurrences": "203K"},
                "exploits": [
                    "Reflected XSS: Inject malicious scripts in URLs",
                    "Stored XSS: Store malicious scripts in database",
                    "DOM-based XSS: Manipulate client-side DOM",
                    "Session Hijacking: Steal session cookies",
                    "Keylogging: Capture user keystrokes"
                ],
                "attack_flow": [
                    "Attacker crafts malicious JavaScript payload",
                    "Injects script into vulnerable input field",
                    "Victim loads page with injected script",
                    "Script executes in victim's browser",
                    "BREACH: Session stolen or account compromised!"
                ],
                "prevention": [
                    "Escape user input before rendering",
                    "Use Content Security Policy (CSP) headers",
                    "Validate and sanitize all user input",
                    "Use framework auto-escaping features",
                    "Set HTTPOnly and Secure flags on cookies"
                ]
            },
            {
                "number": 8,
                "id": "A8",
                "name": "Insecure Deserialization",
                "slug": "insecure-deserialization",
                "risk": "HIGH RISK",
                "description": "Insecure deserialization often leads to remote code execution. Even if deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks.",
                "stats": {"rank": "#8", "apps_tested": "2%", "occurrences": "33K"},
                "exploits": [
                    "Remote Code Execution: Execute arbitrary code",
                    "Replay Attacks: Replay serialized objects",
                    "Privilege Escalation: Modify object properties",
                    "Injection Attacks: Inject malicious data",
                    "Authentication Bypass: Manipulate auth tokens"
                ],
                "attack_flow": [
                    "Attacker intercepts serialized object",
                    "Modifies object to include malicious code",
                    "Sends modified object to application",
                    "Application deserializes without validation",
                    "BREACH: Remote code execution achieved!"
                ],
                "prevention": [
                    "Avoid deserialization of untrusted data",
                    "Implement integrity checks (digital signatures)",
                    "Isolate code that deserializes in low privilege environments",
                    "Log deserialization exceptions and failures",
                    "Use data-only formats like JSON"
                ]
            },
            {
                "number": 9,
                "id": "A9",
                "name": "Using Components with Known Vulnerabilities",
                "slug": "using-components-with-known-vulnerabilities",
                "risk": "HIGH RISK",
                "description": "Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.",
                "stats": {"rank": "#9", "apps_tested": "8%", "occurrences": "132K"},
                "exploits": [
                    "CVE Exploitation: Exploit known vulnerabilities",
                    "Dependency Confusion: Inject malicious packages",
                    "Supply Chain Attacks: Compromise dependencies",
                    "Outdated Libraries: Use unpatched components",
                    "Transitive Dependencies: Exploit nested dependencies"
                ],
                "attack_flow": [
                    "Attacker identifies vulnerable component version",
                    "Searches for public exploits (CVE databases)",
                    "Crafts exploit targeting the vulnerability",
                    "Application processes malicious request",
                    "BREACH: System compromised via component!"
                ],
                "prevention": [
                    "Remove unused dependencies and features",
                    "Continuously inventory component versions",
                    "Monitor CVE databases for vulnerabilities",
                    "Use Software Composition Analysis (SCA) tools",
                    "Obtain components from official sources only"
                ]
            },
            {
                "number": 10,
                "id": "A10",
                "name": "Insufficient Logging & Monitoring",
                "slug": "insufficient-logging-monitoring",
                "risk": "MEDIUM RISK",
                "description": "Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data.",
                "stats": {"rank": "#10", "apps_tested": "6%", "occurrences": "73K"},
                "exploits": [
                    "Undetected Breaches: Attack without detection",
                    "Log Tampering: Modify or delete logs",
                    "Extended Dwell Time: Persist for months",
                    "Privilege Escalation: Escalate undetected",
                    "Data Exfiltration: Steal data over time"
                ],
                "attack_flow": [
                    "Attacker gains initial access",
                    "Performs reconnaissance activities",
                    "No alerts or monitoring triggers",
                    "Escalates privileges and exfiltrates data",
                    "BREACH: Months pass before detection!"
                ],
                "prevention": [
                    "Log all authentication and authorization events",
                    "Ensure logs are immutable and tamper-proof",
                    "Implement real-time monitoring and alerting",
                    "Establish incident response procedures",
                    "Use SIEM for log aggregation and analysis"
                ]
            }
        ]
    },
    "2025": {
        "web": [
            {
                "number": 1,
                "id": "A01",
                "name": "Broken Access Control",
                "slug": "broken-access-control",
                "risk": "CRITICAL RISK",
                "description": "Users can access data or functionality beyond their assigned permissions, leading to unauthorized information disclosure and manipulation.",
                "stats": {"rank": "#1", "apps_tested": "94%", "occurrences": "318K"},
                "exploits": [
                    "Direct Object Reference: Modify URL parameters to access other users' data",
                    "Forced Browsing: Access admin pages by guessing URLs",
                    "Missing Function Level Access Control: Call admin APIs as regular user",
                    "Parameter Tampering: Change user_id, role, or permissions in requests",
                    "Elevation of Privilege: Modify tokens/cookies to gain higher access"
                ],
                "attack_flow": [
                    "Attacker logs in as regular user",
                    "Observes admin button in HTML source",
                    "Accesses /admin endpoint directly",
                    "Server doesn't verify authorization",
                    "BREACH: Admin access granted!"
                ],
                "prevention": [
                    "Deny by default, except for public resources",
                    "Implement centralized access control mechanisms",
                    "Enforce record ownership validation",
                    "Disable directory listing on web servers",
                    "Log access control failures and alert administrators"
                ]
            },
            {
                "number": 2,
                "id": "A02",
                "name": "Cryptographic Failures",
                "slug": "cryptographic-failures",
                "risk": "HIGH RISK",
                "description": "Weak or missing encryption exposes sensitive data in transit and at rest, allowing attackers to steal or modify information.",
                "stats": {"rank": "#2", "apps_tested": "46%", "occurrences": "234K"},
                "exploits": [
                    "Man-in-the-Middle: Intercept unencrypted communications",
                    "Data Breach: Extract unencrypted sensitive data",
                    "Weak Encryption: Break outdated algorithms (MD5, SHA1)",
                    "Missing TLS: Capture credentials in transit",
                    "Insecure Key Storage: Compromise encryption keys"
                ],
                "attack_flow": [
                    "Attacker intercepts network traffic",
                    "Identifies unencrypted or weakly encrypted data",
                    "Captures sensitive information (passwords, credit cards)",
                    "Decrypts using known weaknesses",
                    "BREACH: Sensitive data exposed!"
                ],
                "prevention": [
                    "Encrypt all sensitive data at rest using AES-256",
                    "Use TLS 1.3+ for all data in transit",
                    "Implement proper key management and rotation",
                    "Use strong password hashing (Argon2, bcrypt, scrypt)",
                    "Disable caching for responses with sensitive data"
                ]
            },
            {
                "number": 3,
                "id": "A03",
                "name": "Injection",
                "slug": "injection",
                "risk": "CRITICAL RISK",
                "description": "Untrusted data sent to interpreters (SQL, OS, LDAP) allows attackers to inject malicious code and compromise data integrity.",
                "stats": {"rank": "#3", "apps_tested": "33%", "occurrences": "274K"},
                "exploits": [
                    "SQL Injection: Manipulate database queries to extract data",
                    "NoSQL Injection: Exploit NoSQL databases (MongoDB, etc.)",
                    "OS Command Injection: Execute arbitrary system commands",
                    "LDAP Injection: Manipulate directory service queries",
                    "ORM Injection: Bypass ORM security features"
                ],
                "attack_flow": [
                    "Attacker finds input field accepting user data",
                    "Injects SQL syntax or special characters",
                    "Application builds query without sanitization",
                    "Database executes malicious query",
                    "BREACH: Entire database dumped!"
                ],
                "prevention": [
                    "Use parameterized queries (prepared statements)",
                    "Use Object Relational Mapping (ORM) safely",
                    "Implement server-side input validation",
                    "Apply principle of least privilege to database accounts",
                    "Use SAST tools to detect injection flaws"
                ]
            },
            {
                "number": 4,
                "id": "A04",
                "name": "Insecure Design",
                "slug": "insecure-design",
                "risk": "HIGH RISK",
                "description": "Missing or ineffective security controls in the design phase lead to fundamental security vulnerabilities in applications.",
                "stats": {"rank": "#4", "apps_tested": "40%", "occurrences": "262K"},
                "exploits": [
                    "Business Logic Flaws: Exploit flawed application logic",
                    "Missing Rate Limiting: Abuse functionality without limits",
                    "Insecure Workflows: Bypass security in multi-step processes",
                    "Missing Security Controls: Exploit absent protections",
                    "Race Conditions: Exploit timing vulnerabilities"
                ],
                "attack_flow": [
                    "Attacker analyzes application workflow",
                    "Identifies missing security control",
                    "Exploits design flaw (e.g., no rate limit)",
                    "Repeatedly abuses functionality",
                    "BREACH: Fraud or resource exhaustion!"
                ],
                "prevention": [
                    "Establish secure development lifecycle (SDL)",
                    "Use threat modeling during design phase",
                    "Implement security design patterns",
                    "Use paved road methodology for secure development",
                    "Perform security architecture review"
                ]
            },
            {
                "number": 5,
                "id": "A05",
                "name": "Security Misconfiguration",
                "slug": "security-misconfiguration",
                "risk": "HIGH RISK",
                "description": "Insecure default configurations, incomplete deployments, and unnecessary features leave applications vulnerable to exploitation.",
                "stats": {"rank": "#5", "apps_tested": "90%", "occurrences": "208K"},
                "exploits": [
                    "Default Credentials: Login with default admin passwords",
                    "Directory Listing: Browse exposed directories",
                    "Unnecessary Features: Exploit unused services",
                    "Verbose Error Messages: Extract system information",
                    "Missing Security Headers: Launch XSS/clickjacking attacks"
                ],
                "attack_flow": [
                    "Attacker scans for common misconfigurations",
                    "Discovers default credentials or exposed endpoints",
                    "Accesses administrative panel",
                    "Exploits misconfigured service",
                    "BREACH: Full system control!"
                ],
                "prevention": [
                    "Implement repeatable hardening processes",
                    "Remove unused features, components, and documentation",
                    "Review and update security configurations regularly",
                    "Use segmented application architecture",
                    "Implement automated security configuration scanning"
                ]
            },
            {
                "number": 6,
                "id": "A06",
                "name": "Vulnerable and Outdated Components",
                "slug": "vulnerable-outdated-components",
                "risk": "HIGH RISK",
                "description": "Using components with known vulnerabilities, lack of patching, and outdated software expose applications to exploitation.",
                "stats": {"rank": "#6", "apps_tested": "27%", "occurrences": "179K"},
                "exploits": [
                    "Known CVE Exploitation: Exploit published vulnerabilities",
                    "Dependency Confusion: Inject malicious packages",
                    "Supply Chain Attacks: Compromise package repositories",
                    "Outdated Frameworks: Use old framework versions",
                    "Unpatched Libraries: Exploit vulnerable libraries"
                ],
                "attack_flow": [
                    "Attacker scans application dependencies",
                    "Identifies vulnerable component version",
                    "Finds public exploit for CVE",
                    "Exploits known vulnerability",
                    "BREACH: Remote code execution!"
                ],
                "prevention": [
                    "Remove unused dependencies and features",
                    "Continuously inventory component versions",
                    "Monitor security bulletins and CVE databases",
                    "Only obtain components from official sources",
                    "Use Software Composition Analysis (SCA) tools"
                ]
            },
            {
                "number": 7,
                "id": "A07",
                "name": "Identification and Authentication Failures",
                "slug": "identification-authentication-failures",
                "risk": "HIGH RISK",
                "description": "Weaknesses in authentication mechanisms allow attackers to compromise passwords, keys, session tokens, or exploit implementation flaws.",
                "stats": {"rank": "#7", "apps_tested": "22%", "occurrences": "132K"},
                "exploits": [
                    "Credential Stuffing: Use leaked credential databases",
                    "Brute Force: Automated password guessing",
                    "Session Hijacking: Steal or predict session IDs",
                    "Weak Password Policies: Use common/weak passwords",
                    "Missing MFA: Bypass single-factor authentication"
                ],
                "attack_flow": [
                    "Attacker obtains leaked credential database",
                    "Performs credential stuffing attack",
                    "Application lacks rate limiting",
                    "Valid credentials discovered",
                    "BREACH: Account takeover!"
                ],
                "prevention": [
                    "Implement multi-factor authentication (MFA)",
                    "Use secure session management",
                    "Implement rate limiting and account lockout",
                    "Use strong password hashing (Argon2, bcrypt)",
                    "Prevent credential stuffing with CAPTCHA/device fingerprinting"
                ]
            },
            {
                "number": 8,
                "id": "A08",
                "name": "Software and Data Integrity Failures",
                "slug": "software-data-integrity-failures",
                "risk": "HIGH RISK",
                "description": "Code and infrastructure that do not protect against integrity violations enable malicious code insertion or system compromise.",
                "stats": {"rank": "#8", "apps_tested": "10%", "occurrences": "86K"},
                "exploits": [
                    "Insecure CI/CD: Inject malicious code in pipeline",
                    "Insecure Deserialization: Execute arbitrary code",
                    "Unsigned Updates: Deploy malicious software updates",
                    "Supply Chain Compromise: Tamper with dependencies",
                    "Missing Integrity Checks: Modify application code"
                ],
                "attack_flow": [
                    "Attacker compromises CI/CD pipeline",
                    "Injects malicious code into build",
                    "Application auto-deploys without verification",
                    "Malicious code executes in production",
                    "BREACH: System compromised!"
                ],
                "prevention": [
                    "Use digital signatures to verify software integrity",
                    "Ensure libraries from trusted repositories",
                    "Use Software Bill of Materials (SBOM)",
                    "Review code and configuration changes",
                    "Implement segregation in CI/CD pipeline"
                ]
            },
            {
                "number": 9,
                "id": "A09",
                "name": "Security Logging and Monitoring Failures",
                "slug": "security-logging-monitoring-failures",
                "risk": "MEDIUM RISK",
                "description": "Insufficient logging, detection, monitoring, and active response allow attackers to persist undetected for extended periods.",
                "stats": {"rank": "#9", "apps_tested": "19%", "occurrences": "98K"},
                "exploits": [
                    "Undetected Breaches: Attack without triggering alerts",
                    "Log Tampering: Delete or modify security logs",
                    "Extended Dwell Time: Persist for months undetected",
                    "Insufficient Forensics: Prevent incident investigation",
                    "Delayed Response: Allow damage before detection"
                ],
                "attack_flow": [
                    "Attacker gains initial access",
                    "Performs reconnaissance and lateral movement",
                    "No security alerts generated",
                    "Escalates privileges and exfiltrates data",
                    "BREACH: Attack discovered months later!"
                ],
                "prevention": [
                    "Log all authentication, authorization, and input validation failures",
                    "Ensure logs are tamper-proof and immutable",
                    "Implement effective monitoring and alerting",
                    "Establish incident response and recovery plans",
                    "Use centralized log management (SIEM)"
                ]
            },
            {
                "number": 10,
                "id": "A10",
                "name": "Server-Side Request Forgery (SSRF)",
                "slug": "server-side-request-forgery",
                "risk": "HIGH RISK",
                "description": "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL, enabling attackers to coerce applications into sending requests to unintended destinations.",
                "stats": {"rank": "#10", "apps_tested": "9%", "occurrences": "67K"},
                "exploits": [
                    "Internal Network Scanning: Port scan internal services",
                    "Cloud Metadata Access: Read cloud instance metadata",
                    "Bypass Firewall: Access restricted internal resources",
                    "Data Exfiltration: Send data to attacker-controlled servers",
                    "Remote Code Execution: Exploit internal services"
                ],
                "attack_flow": [
                    "Attacker finds URL parameter accepting external input",
                    "Provides internal URL (e.g., http://localhost:8080/admin)",
                    "Application fetches internal resource",
                    "Returns sensitive internal data to attacker",
                    "BREACH: Internal systems exposed!"
                ],
                "prevention": [
                    "Sanitize and validate all client-supplied input data",
                    "Enforce URL schema, port, and destination with whitelist",
                    "Disable HTTP redirections",
                    "Use network segmentation to isolate resources",
                    "Implement deny-by-default firewall policies"
                ]
            }
        ]
    }
}


def create_cheatsheet_html(year, vuln, category="web"):
    """Generate cheatsheet HTML for a vulnerability"""
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP {year} #{vuln['number']}: {vuln['name']} - Quick Reference</title>
    <link rel="stylesheet" href="../assets/cheat-sheet-style.css">
    <style>
        .back-nav {{
            position: fixed;
            top: 20px;
            left: 20px;
            z-index: 1000;
        }}
        
        .back-btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: var(--darker-color);
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            border: 1px solid var(--primary-color);
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
            transition: all 0.3s;
        }}
        
        .back-btn:hover {{
            transform: translateX(-5px);
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.5);
        }}
        
        .year-badge {{
            background: rgba(0, 255, 65, 0.2);
            color: var(--primary-color);
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.9rem;
            font-weight: 700;
            margin-left: 10px;
        }}
        
        @media print {{
            .back-nav {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="back-nav">
        <a href="../index.html" class="back-btn">
            <i class="fas fa-arrow-left"></i> Back to Cheat Sheets
        </a>
    </div>

    <div class="cheat-sheet">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ {vuln['name']}<span class="year-badge">OWASP {year}</span></h1>
            <p class="subtitle">OWASP {category.upper()} Top 10 {year} - #{vuln['number']}</p>
            <span class="category">{vuln['risk']}</span>
        </div>

        <!-- Main Content -->
        <div class="content">
            <!-- Overview Section -->
            <div class="section full-width">
                <h2>📋 What Is It?</h2>
                <p><strong>{vuln['name']}</strong> - {vuln['description']}</p>
                
                <div class="stats-grid">
                    <div class="stat-box">
                        <span class="value">{vuln['stats']['rank']}</span>
                        <span class="label">OWASP Rank {year}</span>
                    </div>
                    <div class="stat-box">
                        <span class="value">{vuln['stats']['apps_tested']}</span>
                        <span class="label">Apps Tested</span>
                    </div>
                    <div class="stat-box">
                        <span class="value">{vuln['stats']['occurrences']}</span>
                        <span class="label">Occurrences</span>
                    </div>
                </div>
            </div>

            <!-- Common Exploit Patterns -->
            <div class="section">
                <h2>⚠️ Common Exploits</h2>
                <ul>'''
    
    for exploit in vuln['exploits']:
        html += f'\n                    <li>{exploit}</li>'
    
    html += f'''
                </ul>
            </div>

            <!-- Attack Flow -->
            <div class="section">
                <h2>🔴 Attack Flow</h2>
                <div class="attack-flow">'''
    
    for i, step in enumerate(vuln['attack_flow'], 1):
        html += f'\n{i}. {step}<br>'
        if i < len(vuln['attack_flow']):
            html += '\n   <span class="arrow">↓</span><br>'
    
    html += f'''
                </div>
            </div>

            <!-- Prevention Checklist -->
            <div class="section">
                <h2>✓ Prevention Checklist</h2>
                <ul class="checklist">'''
    
    for prevention in vuln['prevention']:
        html += f'\n                    <li>{prevention}</li>'
    
    html += f'''
                </ul>
            </div>

            <!-- Quick Reference -->
            <div class="section full-width">
                <h2>📌 Quick Reference</h2>
                <div class="quick-ref">
                    <div class="ref-item">
                        <strong>Risk Level:</strong> {vuln['risk']}
                    </div>
                    <div class="ref-item">
                        <strong>Year:</strong> OWASP Top 10 {year}
                    </div>
                    <div class="ref-item">
                        <strong>Category:</strong> {category.upper()}
                    </div>
                    <div class="ref-item">
                        <strong>Ranking:</strong> #{vuln['number']} in {year}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</body>
</html>'''
    
    return html


def generate_all_content():
    """Generate all cheatsheets for 2017 and 2025"""
    # Use relative path from script location
    base_path = Path(__file__).parent
    
    for year in ["2017", "2025"]:
        print(f"\n🚀 Generating content for OWASP {year}...")
        
        # Create year-specific directory structure
        year_dir = base_path / "cheat-sheets" / year
        web_dir = year_dir / "web"
        web_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate cheatsheets
        for vuln in OWASP_DATA[year]["web"]:
            filename = f"{vuln['number']:02d}-{vuln['slug']}.html"
            filepath = web_dir / filename
            
            html_content = create_cheatsheet_html(year, vuln)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"  ✅ Created {filepath.relative_to(base_path)}")
        
        print(f"\n✨ Completed {year}: {len(OWASP_DATA[year]['web'])} cheatsheets generated")


if __name__ == "__main__":
    generate_all_content()
    print("\n🎉 All content generated successfully!")
