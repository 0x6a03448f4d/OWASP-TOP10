# Insufficient Logging & Monitoring - Overview

## What is the Problem?

**Insufficient logging and monitoring** allows attackers to:
- Achieve their goals without being detected
- Maintain persistence
- Tamper with or destroy evidence
- Attack additional systems

Without adequate logging and monitoring:
- Breaches go undetected for months
- Incident response is severely hampered
- Attack patterns cannot be identified

## Why This Matters

In 2017, this was #10 in OWASP Top 10:

- Average breach detection time: 197 days
- Many breaches discovered by external parties
- Insufficient audit trails hindered investigations
- Regulatory requirements (PCI-DSS, GDPR) demand logging

## What Should Be Logged?

Critical events to log:
- Login attempts (successful and failed)
- Access control failures
- Input validation failures
- Authentication failures
- Session management events
- Application errors and exceptions
- System events (startup, shutdown)

## Real-World Impact

**Equifax (2017)**
- Breach went undetected for 76 days
- Inadequate monitoring of critical systems
- Failed to detect data exfiltration

**Target (2013, lessons learned by 2017)**
- Security alerts were ignored
- 40 million credit cards stolen
- Monitoring tools in place but not acted upon
