# Attack Scripts for API05 Lab

This directory contains example attack scripts demonstrating various function-level authorization exploits.

## Scripts

1. **privilege_escalation.py** - Register as admin using mass assignment
2. **admin_access.py** - Access admin endpoints as regular user
3. **user_deletion.py** - Delete users without authorization
4. **role_manipulation.py** - Change user roles without permission
5. **product_manipulation.py** - Modify product prices
6. **bulk_operations.py** - Exploit bulk delete operations
7. **automated_attack.py** - Automated full exploitation chain

## Usage

```bash
# Install dependencies
pip install requests

# Run individual attacks
python privilege_escalation.py
python admin_access.py
python user_deletion.py

# Or run the full automated attack
python automated_attack.py
```

## Warning

⚠️ These scripts are for educational purposes only. Only use them against the lab environment or systems you have explicit permission to test.
