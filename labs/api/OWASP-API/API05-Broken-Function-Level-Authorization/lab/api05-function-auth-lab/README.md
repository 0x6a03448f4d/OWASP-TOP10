# API05: Broken Function Level Authorization Lab

A hands-on lab environment to practice discovering and exploiting function-level authorization vulnerabilities.

## Quick Start

```bash
# Start the lab
docker-compose up

# Access the web interface
open http://localhost:5000

# Or use the API directly
curl http://localhost:5000/api/info
```

## Test Accounts

| Username | Password    | Role  |
|----------|-------------|-------|
| alice    | password123 | user  |
| bob      | password123 | user  |
| admin    | admin123    | admin |

## Lab Objectives

1. **Discover** function-level authorization vulnerabilities
2. **Exploit** admin endpoints as a regular user
3. **Understand** the impact of missing role checks
4. **Learn** how to properly implement authorization

## Vulnerabilities Included

- Mass assignment (role in registration)
- Admin endpoints without authorization checks
- Method-specific authorization gaps
- Hidden debug endpoints
- Settings manipulation
- Audit log exposure
- Bulk operations without proper checks

## Lab Structure

```
api05-function-auth-lab/
├── app/
│   ├── server.py          # Vulnerable Flask API
│   ├── templates/
│   │   └── index.html     # Web interface
│   ├── requirements.txt
│   └── Dockerfile
├── attacks/               # Attack scripts and examples
├── solution/             # Secure implementation
├── docker-compose.yml
├── instructions.md       # Detailed lab guide
└── README.md            # This file
```

## Next Steps

See [instructions.md](instructions.md) for detailed exercises and learning objectives.
