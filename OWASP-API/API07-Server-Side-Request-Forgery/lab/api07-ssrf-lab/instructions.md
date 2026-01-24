# API07: SSRF Lab - Instructions

## Setup
```bash
docker-compose up -d
```
Access: http://localhost:5007

## Exercise 1: Basic SSRF
Try accessing internal endpoints:
```
http://localhost:5000/internal/metadata
http://localhost:5000/internal/database
```

## Exercise 2: Cloud Metadata (Simulated)
Access simulated AWS metadata:
```
http://localhost:5000/internal/metadata
```

## Exercise 3: File System Access
Try reading local files (if on Linux):
```
file:///etc/passwd
file:///proc/self/environ
```

## Exercise 4: Port Scanning
Scan for internal services:
```
http://localhost:6379 (Redis)
http://localhost:3306 (MySQL)
```

## Exercise 5: Implement Protection
Add URL validation to prevent SSRF.

## Success Criteria
- ✅ Access internal metadata
- ✅ Read local files
- ✅ Understand SSRF impact
- ✅ Implement validation
