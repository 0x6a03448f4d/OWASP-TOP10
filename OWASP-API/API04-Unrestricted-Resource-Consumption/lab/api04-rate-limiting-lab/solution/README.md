# Solution: Secure API with Resource Controls

This directory contains the secured version of the API with proper defenses against unrestricted resource consumption.

## Key Security Improvements

### 1. Rate Limiting
- Flask-Limiter with configurable limits per endpoint
- Different limits for different endpoint sensitivity
- Memory-backed storage (use Redis in production)

### 2. Pagination
- All list endpoints support pagination
- Maximum page size enforced (100 items)
- Total count and page metadata provided

### 3. Request Size Limits
- 10MB maximum request size
- Proper error handling for oversized requests

### 4. Batch Operation Limits
- Maximum batch size of 100 items
- Clear error messages when limits exceeded

### 5. Timeout Protection
- Query timeouts to prevent long-running operations
- Graceful timeout error handling

### 6. Input Validation
- Strict validation of all parameters
- Type checking and bounds validation

## How to Use

### Option 1: Replace Vulnerable Files

```bash
# Backup original files
cp app/requirements.txt app/requirements.txt.backup
cp app/server.py app/server.py.backup

# Copy solution files
cp solution/requirements.txt app/
cp solution/server_secure.py app/server.py

# Rebuild and restart
docker-compose down
docker-compose build
docker-compose up -d
```

### Option 2: Run Solution Separately

You can also compare the vulnerable and secure versions side-by-side by running them on different ports.

## Testing the Solution

### Verify Rate Limiting

```bash
# This should block after 5 attempts
for i in {1..10}; do
  curl -X POST http://localhost:5004/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"test"}'
  echo ""
done
```

Expected: First 5 succeed, then 429 (Too Many Requests)

### Verify Pagination

```bash
# Should return only 10 users, not all 10,000
curl "http://localhost:5004/api/users?page=1&per_page=10"
```

### Verify Batch Limits

```bash
# This should be rejected (too large)
python3 -c "
import requests
items = [{'data': f'item-{i}'} for i in range(1000)]
r = requests.post('http://localhost:5004/api/batch/process', json={'items': items})
print(f'Status: {r.status_code}, Response: {r.json()}')
"
```

Expected: 400 (Bad Request) with "Batch size exceeds maximum" message

### Re-run Attack Scripts

All attack scripts from the `attacks/` directory should now fail or be throttled:

```bash
cd ../attacks
python3 flood_attack.py      # Should hit rate limits
python3 cpu_attack.py        # Should hit rate limits
python3 brute_force_attack.py # Should be blocked after 5 attempts
```

## Rate Limit Configuration

The solution uses these limits:

| Endpoint | Limit | Reason |
|----------|-------|--------|
| Global default | 100/hour | Prevent abuse |
| `/api/login` | 5/minute | Prevent brute force |
| `/api/users` | 60/minute | Allow reasonable access |
| `/api/orders` | 60/minute | Allow reasonable access |
| `/api/generate-report` | 2/minute | Very expensive operation |
| `/api/batch/process` | 10/minute | Resource intensive |
| `/api/search` | 30/minute | Moderate cost |

## Production Considerations

For production deployments, enhance with:

1. **Redis-backed rate limiting** for distributed systems
2. **User-specific quotas** based on subscription tier
3. **Cost-based rate limiting** (different endpoints have different costs)
4. **Monitoring and alerting** on rate limit hits
5. **Dynamic rate limits** based on system load
6. **IP-based and user-based limits** combined
7. **Graceful degradation** instead of hard failures

See `production_example.py` for advanced patterns.
