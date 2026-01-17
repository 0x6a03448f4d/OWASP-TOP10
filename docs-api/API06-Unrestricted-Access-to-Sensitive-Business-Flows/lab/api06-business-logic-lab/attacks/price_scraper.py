#!/usr/bin/env python3
import requests
import time
import json

API_URL = "http://localhost:5006/api"

def price_scraping_attack(iterations=100):
    print(f"[*] Price scraping attack ({iterations} iterations)")
    
    catalog_data = []
    
    for i in range(iterations):
        try:
            response = requests.get(f"{API_URL}/products")
            
            if response.status_code == 200:
                products = response.json()
                timestamp = time.time()
                
                catalog_data.append({
                    'timestamp': timestamp,
                    'products': products
                })
                
                print(f"[+] Scrape {i+1}/{iterations}: {len(products)} products")
            else:
                print(f"[-] Scrape {i+1} failed: {response.status_code}")
            
            time.sleep(0.1)  # 10 requests per second
            
        except Exception as e:
            print(f"[-] Error: {e}")
    
    # Save scraped data
    with open('scraped_catalog.json', 'w') as f:
        json.dump(catalog_data, f, indent=2)
    
    print(f"\n[*] Scraping complete!")
    print(f"[*] Collected {len(catalog_data)} snapshots")
    print(f"[*] Data saved to scraped_catalog.json")

if __name__ == "__main__":
    price_scraping_attack(iterations=100)
