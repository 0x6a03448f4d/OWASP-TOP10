# M02: Supply Chain Security Lab - Dependency Vulnerabilities

## Overview

This lab demonstrates inadequate supply chain security through a mock package management scenario. You'll explore how vulnerable dependencies, missing integrity checks, and lack of monitoring can compromise applications.

**Learning Objectives:**
- Identify vulnerable dependencies in a project
- Understand the impact of using wildcards in version specifications
- Learn to use dependency scanning tools
- Practice secure dependency management

**Lab Environment:**
- Flask web application simulating a package manager
- Mock vulnerable dependencies database
- Dependency scanning simulator
- SBOM generation demonstration

## Lab Architecture

```
┌─────────────────────────────────────────┐
│     Package Management Dashboard        │
│  ┌───────────────────────────────────┐  │
│  │  Current Dependencies             │  │
│  │  - axios: ^1.2.0 (Vulnerable!)    │  │
│  │  - lodash: * (Risky!)             │  │
│  │  - react: 18.2.0 (Secure)         │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │  Security Scanner                 │  │
│  │  └─ Run Audit                     │  │
│  │  └─ Generate SBOM                 │  │
│  │  └─ Check Integrity               │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Prerequisites

- Docker and Docker Compose installed
- Basic understanding of package managers (npm, pip, etc.)
- Web browser

## Setup Instructions

### 1. Start the Lab

```bash
cd OWASP-Mobile/M02-Inadequate-Supply-Chain-Security/lab/m02-supply-chain-lab
docker-compose up --build
```

### 2. Access the Application

Open your browser to: **http://localhost:5000**

### 3. Test Accounts

No authentication required for this lab - it's a package management simulator.

## Lab Environment Details

**Services Running:**
- **Web App**: Port 5000 - Package management dashboard
- **Mock Registry**: Simulated package repository

**Features:**
- View current dependencies
- Run vulnerability scans
- Generate Software Bill of Materials (SBOM)
- Compare vulnerable vs secure configurations

## What You'll Learn

1. **Dependency Vulnerabilities**
   - How to identify outdated packages
   - Understanding severity levels
   - Impact of transitive dependencies

2. **Version Management**
   - Risks of wildcard versions
   - Benefits of lock files
   - Semantic versioning importance

3. **Security Scanning**
   - Running dependency audits
   - Interpreting vulnerability reports
   - Prioritizing remediation

4. **Best Practices**
   - SBOM generation and use
   - Integrity verification
   - Continuous monitoring

## Lab Scenarios

### Scenario 1: Vulnerable Dependencies
The application includes intentionally vulnerable dependencies to demonstrate real-world risks.

### Scenario 2: Missing Lock Files
Explore the implications of not using package-lock.json or similar files.

### Scenario 3: Wildcard Versions
See how wildcard version specifications can lead to unexpected updates.

## Stopping the Lab

```bash
# Stop the containers
docker-compose down

# Clean up volumes
docker-compose down -v
```

## Troubleshooting

**Port 5000 already in use:**
```bash
# Option 1: Stop the conflicting service
lsof -i :5000  # Find the process
kill <PID>

# Option 2: Change the port in docker-compose.yml
ports:
  - "5001:5000"
```

**Docker issues:**
```bash
# Rebuild from scratch
docker-compose down -v
docker-compose build --no-cache
docker-compose up
```

## Next Steps

After completing the lab:
1. Review [prevention.md](../prevention.md) for mitigation strategies
2. Explore [examples.md](../examples.md) for code patterns
3. Practice with your own projects using learned techniques

## Educational Notes

⚠️ **This is a learning environment**
- Uses mock vulnerability database
- Demonstrates concepts safely
- No actual malicious code
- Isolated from production systems

---

**Remember**: Your application security is only as strong as your weakest dependency!
