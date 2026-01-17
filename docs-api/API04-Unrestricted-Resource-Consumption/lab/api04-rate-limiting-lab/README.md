# API04: Rate Limiting Lab

## Overview

This hands-on lab demonstrates **API04: Unrestricted Resource Consumption** vulnerabilities. You'll exploit an API with no rate limiting, pagination, or resource controls, then implement proper defenses.

## Learning Objectives

By completing this lab, you will:

1. **Understand** how resource exhaustion attacks work
2. **Exploit** APIs lacking rate limiting and resource controls
3. **Implement** various rate limiting strategies
4. **Configure** pagination and query limits
5. **Apply** resource quotas and timeouts
6. **Monitor** API usage patterns

## Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Vulnerable API                      │
│  ┌────────────────────────────────────────────────┐ │
│  │  Flask Application (server.py)                 │ │
│  │  - No rate limiting                            │ │
│  │  - No pagination                               │ │
│  │  - Expensive operations                        │ │
│  │  - No timeouts                                 │ │
│  └────────────────────────────────────────────────┘ │
│                       │                              │
│                       ▼                              │
│  ┌────────────────────────────────────────────────┐ │
│  │  SQLite Database                               │ │
│  │  - 100,000+ records                            │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- Docker and Docker Compose installed
- Basic Python knowledge
- Understanding of REST APIs
- `curl`, `httpie`, or similar HTTP client
- (Optional) Python with `requests` library for attack scripts

## Quick Start

```bash
# 1. Navigate to lab directory
cd docs-api/API04-Unrestricted-Resource-Consumption/lab/api04-rate-limiting-lab/

# 2. Start the vulnerable API
docker-compose up -d

# 3. Verify it's running
curl http://localhost:5004/health

# 4. Open the web interface
open http://localhost:5004/

# 5. Follow instructions.md for exercises
```

## What's Included

### Vulnerable Endpoints

1. **`GET /api/users`** - No pagination, returns all users
2. **`POST /api/login`** - No rate limiting on authentication
3. **`GET /api/search`** - Expensive search with no limits
4. **`POST /api/generate-report`** - CPU-intensive operation
5. **`POST /api/batch/process`** - Unlimited batch size
6. **`POST /api/upload`** - No file size limits

### Attack Scripts

Pre-written Python scripts to exploit vulnerabilities:
- `attacks/flood_requests.py` - Request flooding
- `attacks/cpu_exhaustion.py` - CPU exhaustion
- `attacks/memory_exhaustion.py` - Memory exhaustion

### Exercises

1. **Reconnaissance** - Identify expensive endpoints
2. **Volume Attack** - Overwhelm with requests
3. **Complexity Attack** - Exploit expensive operations
4. **Batch Abuse** - Overload batch processing
5. **Implement Defenses** - Add rate limiting and controls

## Expected Outcomes

### Phase 1: Exploitation (30 minutes)

- Crash the API with request flooding
- Exhaust CPU with expensive operations
- Fill memory with unbounded queries
- Understand attack economics

### Phase 2: Defense (45 minutes)

- Implement rate limiting
- Add pagination
- Set query timeouts
- Configure resource limits

### Phase 3: Testing (15 minutes)

- Verify defenses work
- Test legitimate usage still works
- Measure performance improvements

## Success Criteria

You've completed the lab when you can:

1. ✅ Successfully crash the vulnerable API
2. ✅ Explain why each vulnerability is dangerous
3. ✅ Implement working rate limiting
4. ✅ Add pagination to list endpoints
5. ✅ Set appropriate timeouts
6. ✅ Verify your defenses prevent attacks

## Next Steps

After completing this lab:

1. Review [prevention.md](../../prevention.md) for advanced techniques
2. Explore [examples.md](../../examples.md) for production patterns
3. Apply these protections to your own APIs

## Troubleshooting

**API won't start:**
```bash
docker-compose down -v
docker-compose up --build
```

**Port 5004 already in use:**
```bash
# Edit docker-compose.yml and change port mapping
# From: "5004:5000"
# To:   "5005:5000"
```

**Database not seeding:**
```bash
docker-compose exec api python seed_db.py
```

## Support

For issues or questions:
1. Check [instructions.md](./instructions.md) for detailed steps
2. Review [hints.md](./hints.md) if stuck
3. Check `docker-compose logs api` for errors

## Warning

⚠️ **This is a deliberately vulnerable application.** 

- Only run in isolated environments
- Never expose to the internet
- Do not use code patterns in production without fixes
- All attacks should target localhost only

## Lab Structure

```
api04-rate-limiting-lab/
├── README.md                 # This file
├── instructions.md           # Detailed lab instructions
├── hints.md                  # Hints for each exercise
├── solutions/                # Reference solutions
│   ├── rate_limiting.py
│   ├── pagination.py
│   └── complete_solution.py
├── docker-compose.yml        # Container orchestration
├── app/
│   ├── server.py            # Vulnerable Flask application
│   ├── requirements.txt     # Python dependencies
│   ├── seed_db.py          # Database seeding script
│   └── templates/
│       └── index.html       # Web interface
└── attacks/                 # Attack scripts
    ├── flood_requests.py
    ├── cpu_exhaustion.py
    └── memory_exhaustion.py
```

Happy hacking! 🔓🚀
