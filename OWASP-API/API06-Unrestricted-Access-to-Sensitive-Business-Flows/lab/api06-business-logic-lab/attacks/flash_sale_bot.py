#!/usr/bin/env python3
import requests
import time
from datetime import datetime

API_URL = "http://localhost:5006/api"

def flash_sale_bot(product_id, target_time=None):
    print("[*] Flash sale bot initialized")
    print(f"[*] Target product: {product_id}")
    
    if target_time:
        print(f"[*] Waiting until {target_time}")
        # In real attack, would wait until exact time
        # For demo, proceed immediately
    
    print("[*] Sale started - executing rapid purchases!")
    
    # Pre-prepared request for maximum speed
    payload = {
        'user_id': 1,
        'product_id': product_id,
        'quantity': 5,  # Max allowed
        'coupons': ['FLASH50']  # Pre-applied coupon
    }
    
    start = time.time()
    
    # Rapid fire purchases
    for i in range(10):
        try:
            response = requests.post(f"{API_URL}/purchase", json=payload, timeout=2)
            
            if response.status_code == 200:
                data = response.json()
                print(f"[+] Purchase {i+1}: SUCCESS - Order #{data['order_id']}")
            else:
                print(f"[-] Purchase {i+1}: FAILED - {response.json()}")
        except Exception as e:
            print(f"[-] Purchase {i+1}: ERROR - {e}")
    
    elapsed = (time.time() - start) * 1000  # Convert to milliseconds
    print(f"\n[*] Completed 10 purchases in {elapsed:.0f}ms")
    print(f"[*] Average: {elapsed/10:.0f}ms per purchase")
    print(f"[*] Human users had no chance!")

if __name__ == "__main__":
    flash_sale_bot(product_id=1)
