# Broken Access Control Lab: Admin Button Vulnerability

## Overview

This lab demonstrates a common **Broken Access Control** vulnerability where administrative functions are hidden from regular users in the UI, but the underlying endpoints are not properly protected on the server side.

## Vulnerability Demonstrated

**Client-Side Access Control**: The application relies on hiding the "Admin Panel" button from non-admin users, but anyone who knows the URL (`/admin`) can access it directly.

This is a critical vulnerability because:
- 🔴 **Security through obscurity doesn't work**
- 🔴 **UI restrictions can be easily bypassed**
- 🔴 **Server must enforce all authorization**

## Learning Objectives

By completing this lab, you will:

1. ✅ Understand why client-side access control is insufficient
2. ✅ Learn to identify missing server-side authorization checks
3. ✅ Discover how attackers can access hidden functionality
4. ✅ Practice fixing broken access control vulnerabilities
5. ✅ Understand the principle of "defense in depth"

## Prerequisites

- Docker and Docker Compose installed
- Basic understanding of web applications
- Familiarity with Flask/Python (helpful but not required)

## Quick Start

### 1. Start the Lab

```bash
docker-compose up
```

The application will be available at: **http://localhost:5000**

### 2. Test Accounts

- **Regular User 1**: `alice` / `password123`
- **Regular User 2**: `bob` / `password123`
- **Administrator**: `admin` / `admin123`

### 3. Stop the Lab

```bash
docker-compose down
```

## Lab Structure

```
broken-access-control-adminbutton/
├── docker-compose.yml          # Docker configuration
├── app/
│   ├── server.py              # Flask application (VULNERABLE)
│   ├── requirements.txt       # Python dependencies
│   └── templates/
│       ├── home.html         # Login page and user dashboard
│       └── admin.html        # Admin panel (UNPROTECTED!)
├── README.md                  # This file
└── instructions.md           # Step-by-step lab guide
```

## What You'll Discover

### The Vulnerability

The application has two critical flaws:

1. **Hidden Admin Button**: Regular users don't see the admin button in the UI
2. **Unprotected Endpoint**: The `/admin` route has NO authorization check
3. **Vulnerable API**: The `/api/admin/secrets` endpoint is also unprotected

### How It Works (Conceptual)

```python
# VULNERABLE CODE (simplified):
@app.route('/admin')
def admin_panel():
    # Uh oh! No authorization check here
    return render_template('admin.html')

# The UI hides the button:
{% if role == 'admin' %}
  <button>Admin Panel</button>  <!-- Hidden for regular users -->
{% endif %}

# But the /admin URL is still accessible!
```

## Safety Features

This lab is completely safe for educational use:

- ✅ Runs in isolated Docker container
- ✅ No real sensitive data
- ✅ Local-only (no external network access)
- ✅ Uses in-memory database (no persistence)
- ✅ Educational comments throughout code
- ✅ Cannot harm your system

## Common Issues

### Port Already in Use

If port 5000 is already in use:

```bash
# Option 1: Stop the conflicting service
lsof -i :5000  # Find what's using it
kill <PID>

# Option 2: Use a different port
# Edit docker-compose.yml: "5001:5000"
```

### Docker Not Running

```bash
# Start Docker Desktop or:
sudo systemctl start docker  # Linux
```

### Permission Denied

```bash
# Run with sudo (if needed)
sudo docker-compose up
```

## Next Steps

1. Read the **[instructions.md](./instructions.md)** for guided tasks
2. Explore the vulnerability yourself
3. Try to fix the code
4. Test your fix thoroughly

## Related Documentation

- **[Overview](../../overview.md)**: Understand broken access control
- **[Attack Vectors](../../attack-vectors.md)**: How attacks happen
- **[Prevention](../../prevention.md)**: Best practices
- **[Examples](../../examples.md)**: More code examples

## Educational Use Only

⚠️ **IMPORTANT**: This lab is for learning defensive security practices. The techniques demonstrated should NEVER be used against real systems without explicit authorization.

## Support

If you encounter issues:
1. Check the [Common Issues](#common-issues) section
2. Review the Docker logs: `docker-compose logs`
3. Open an issue on the repository

---

*Part of the [OWASP Top 10 Educational Repository](../../../../../README.md)*
