# Attack Scripts

This directory contains educational attack scripts that demonstrate API04: Unrestricted Resource Consumption vulnerabilities.

## ⚠️ Ethical Use Only

These scripts are for **educational purposes only**. Use them only against the vulnerable lab API running on localhost.

## Attack Scripts

### 1. flood_attack.py
Demonstrates request flooding without rate limiting.

```bash
python3 flood_attack.py
```

**Attack**: Sends hundreds of concurrent requests to overwhelm the API.
**Impact**: API becomes slow or unresponsive, affecting legitimate users.

### 2. cpu_attack.py
Demonstrates CPU exhaustion through expensive operations.

```bash
python3 cpu_attack.py
```

**Attack**: Triggers resource-intensive report generation concurrently.
**Impact**: Server CPU usage spikes to 100%, degrading performance.

### 3. memory_attack.py
Demonstrates memory exhaustion through large responses.

```bash
python3 memory_attack.py
```

**Attack**: Requests multiple large datasets concurrently and holds them in memory.
**Impact**: Server memory fills up, potentially causing crashes.

### 4. batch_attack.py
Demonstrates batch operation abuse.

```bash
python3 batch_attack.py
```

**Attack**: Sends oversized batch processing requests.
**Impact**: Server hangs processing massive batches, blocking other requests.

### 5. brute_force_attack.py
Demonstrates authentication brute forcing without rate limiting.

```bash
python3 brute_force_attack.py
```

**Attack**: Attempts unlimited login attempts.
**Impact**: Enables password guessing and account takeover.

## Requirements

```bash
pip install requests
```

## Monitoring

While running attacks, monitor resource usage:

```bash
# Watch Docker container stats
docker stats api04-vulnerable-api

# Check API health
curl http://localhost:5004/health
```

## Defense

After running these attacks, implement the defenses in the `solution/` directory to protect against them.
