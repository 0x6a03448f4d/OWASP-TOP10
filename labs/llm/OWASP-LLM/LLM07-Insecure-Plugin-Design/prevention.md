# LLM07: Insecure Plugin Design - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Input Validation](#input-validation)
- [Authentication and Authorization](#authentication-and-authorization)
- [Secure Plugin Architecture](#secure-plugin-architecture)
- [SSRF Prevention](#ssrf-prevention)
- [Command Injection Prevention](#command-injection-prevention)
- [Path Traversal Prevention](#path-traversal-prevention)
- [Rate Limiting and Resource Controls](#rate-limiting-and-resource-controls)
- [Monitoring and Logging](#monitoring-and-logging)
- [Best Practices](#best-practices)

## Prevention Strategy Overview

Preventing plugin vulnerabilities requires defense-in-depth with multiple security layers across the entire plugin lifecycle.

### Defense Layers

```
[User Input] → [LLM] → [Plugin Validator] → [Authorization] → [Sandboxed Execution]
     ↓            ↓           ↓                    ↓                  ↓
  Validated   Sanitized  Type Checked         Permissions      Restricted Access
  Filtered    Encoded    Schema Valid         Verified         Resource Limited
```

## Input Validation

### 1. Comprehensive Input Validation Framework

**Validate all plugin inputs before execution**:

```python
from typing import Any, Dict, List, Optional
import re
from urllib.parse import urlparse

class PluginInputValidator:
    """Comprehensive input validation for plugins"""
    
    def __init__(self):
        self.allowed_url_schemes = ['http', 'https']
        self.max_string_length = 10000
        self.max_array_size = 1000
    
    def validate_string(self, value: str, 
                       pattern: Optional[str] = None,
                       max_length: Optional[int] = None) -> bool:
        """Validate string input"""
        if not isinstance(value, str):
            raise ValueError("Input must be string")
        
        # Length check
        max_len = max_length or self.max_string_length
        if len(value) > max_len:
            raise ValueError(f"String exceeds maximum length: {max_len}")
        
        # Pattern validation if provided
        if pattern and not re.match(pattern, value):
            raise ValueError(f"String doesn't match required pattern")
        
        # Check for null bytes
        if '\x00' in value:
            raise ValueError("Null bytes not allowed")
        
        return True
    
    def validate_url(self, url: str, 
                    allowed_domains: Optional[List[str]] = None) -> bool:
        """Validate URL input"""
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in self.allowed_url_schemes:
                raise ValueError(f"URL scheme not allowed: {parsed.scheme}")
            
            # Check for localhost/internal IPs
            hostname = parsed.hostname
            if self.is_internal_address(hostname):
                raise ValueError(f"Access to internal addresses not allowed")
            
            # Check domain allowlist if provided
            if allowed_domains:
                if not any(allowed in hostname for allowed in allowed_domains):
                    raise ValueError(f"Domain not in allowlist: {hostname}")
            
            return True
        
        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")
    
    def is_internal_address(self, hostname: str) -> bool:
        """Check if hostname points to internal/private network"""
        import ipaddress
        
        # Check for localhost
        if hostname in ['localhost', '127.0.0.1', '::1']:
            return True
        
        # Check for private IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            # Not an IP, check for metadata endpoints
            metadata_endpoints = [
                'metadata.google.internal',
                '169.254.169.254',
                'metadata.azure.com',
            ]
            return any(endpoint in hostname for endpoint in metadata_endpoints)
    
    def validate_file_path(self, path: str, 
                          allowed_directory: str) -> bool:
        """Validate file path is within allowed directory"""
        import os
        
        # Resolve to absolute path
        abs_path = os.path.abspath(path)
        abs_allowed = os.path.abspath(allowed_directory)
        
        # Check if path is within allowed directory
        common_path = os.path.commonpath([abs_path, abs_allowed])
        if common_path != abs_allowed:
            raise ValueError(f"Path outside allowed directory: {path}")
        
        # Check for suspicious patterns
        suspicious = ['..', '~', '${', '$(',]
        if any(pattern in path for pattern in suspicious):
            raise ValueError(f"Suspicious pattern in path: {path}")
        
        return True
    
    def validate_sql_identifier(self, identifier: str) -> bool:
        """Validate SQL identifier (table/column name)"""
        # Only allow alphanumeric and underscore
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
            raise ValueError(f"Invalid SQL identifier: {identifier}")
        
        # Check length
        if len(identifier) > 64:
            raise ValueError("SQL identifier too long")
        
        # Blacklist SQL keywords
        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
            'ALTER', 'EXEC', 'EXECUTE', 'UNION', 'OR', 'AND'
        ]
        if identifier.upper() in sql_keywords:
            raise ValueError(f"SQL keyword not allowed: {identifier}")
        
        return True
    
    def validate_command_args(self, args: List[str]) -> bool:
        """Validate command arguments"""
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '>', '<']
        
        for arg in args:
            # Check for command injection characters
            if any(char in arg for char in dangerous_chars):
                raise ValueError(f"Dangerous character in argument: {arg}")
            
            # Check for command substitution
            if '$(' in arg or '`' in arg:
                raise ValueError(f"Command substitution not allowed: {arg}")
        
        return True

# Usage
validator = PluginInputValidator()

def secure_database_plugin(table: str, query: str):
    """Secure database plugin with validation"""
    try:
        # Validate table name
        validator.validate_sql_identifier(table)
        
        # Validate query string
        validator.validate_string(query, max_length=1000)
        
        # Additional validation: use parameterized queries
        # ... proceed with query execution
        
    except ValueError as e:
        return {"error": f"Validation failed: {e}"}
```

### 2. Schema-Based Validation

**Define and enforce plugin input schemas**:

```python
from typing import Any, Dict
from jsonschema import validate, ValidationError
import jsonschema

class PluginSchemaValidator:
    """Schema-based validation for plugin inputs"""
    
    def __init__(self):
        self.schemas = {}
    
    def register_plugin_schema(self, plugin_name: str, schema: Dict):
        """Register JSON schema for plugin"""
        self.schemas[plugin_name] = schema
    
    def validate_plugin_input(self, plugin_name: str, 
                             parameters: Dict) -> bool:
        """Validate plugin input against registered schema"""
        if plugin_name not in self.schemas:
            raise ValueError(f"No schema registered for plugin: {plugin_name}")
        
        try:
            validate(instance=parameters, schema=self.schemas[plugin_name])
            return True
        except ValidationError as e:
            raise ValueError(f"Schema validation failed: {e.message}")

# Define schemas
schema_validator = PluginSchemaValidator()

# Database plugin schema
database_schema = {
    "type": "object",
    "properties": {
        "table": {
            "type": "string",
            "pattern": "^[a-zA-Z_][a-zA-Z0-9_]*$",
            "maxLength": 64
        },
        "filters": {
            "type": "object",
            "additionalProperties": {
                "type": ["string", "number", "boolean"]
            }
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 1000
        }
    },
    "required": ["table"],
    "additionalProperties": False
}

schema_validator.register_plugin_schema("database", database_schema)

# URL fetch plugin schema
url_fetch_schema = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "format": "uri",
            "pattern": "^https://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/.*)?$"
        },
        "method": {
            "type": "string",
            "enum": ["GET", "POST"]
        },
        "timeout": {
            "type": "integer",
            "minimum": 1,
            "maximum": 30
        }
    },
    "required": ["url"],
    "additionalProperties": False
}

schema_validator.register_plugin_schema("url_fetch", url_fetch_schema)

# Usage
def execute_plugin(plugin_name: str, parameters: Dict):
    """Execute plugin with schema validation"""
    try:
        # Validate against schema
        schema_validator.validate_plugin_input(plugin_name, parameters)
        
        # Execute plugin
        return plugins[plugin_name](**parameters)
    
    except ValueError as e:
        return {"error": str(e)}
```

## Authentication and Authorization

### 1. Role-Based Access Control (RBAC)

**Implement proper authorization for plugins**:

```python
from enum import Enum
from typing import Set, Dict, Optional
from functools import wraps

class Role(Enum):
    ADMIN = "admin"
    USER = "user"
    READONLY = "readonly"

class Permission(Enum):
    READ_DATA = "read_data"
    WRITE_DATA = "write_data"
    EXECUTE_COMMAND = "execute_command"
    ACCESS_ADMIN = "access_admin"
    READ_FILES = "read_files"
    WRITE_FILES = "write_files"

class PluginAuthorizationManager:
    """Manage plugin access control"""
    
    def __init__(self):
        # Define role permissions
        self.role_permissions: Dict[Role, Set[Permission]] = {
            Role.ADMIN: {
                Permission.READ_DATA,
                Permission.WRITE_DATA,
                Permission.EXECUTE_COMMAND,
                Permission.ACCESS_ADMIN,
                Permission.READ_FILES,
                Permission.WRITE_FILES,
            },
            Role.USER: {
                Permission.READ_DATA,
                Permission.WRITE_DATA,
                Permission.READ_FILES,
            },
            Role.READONLY: {
                Permission.READ_DATA,
                Permission.READ_FILES,
            }
        }
        
        # Define plugin permission requirements
        self.plugin_permissions: Dict[str, Set[Permission]] = {
            "database_write": {Permission.WRITE_DATA},
            "database_read": {Permission.READ_DATA},
            "file_read": {Permission.READ_FILES},
            "file_write": {Permission.WRITE_FILES},
            "system_command": {Permission.EXECUTE_COMMAND},
            "admin_panel": {Permission.ACCESS_ADMIN},
        }
    
    def has_permission(self, user_role: Role, 
                      required_permission: Permission) -> bool:
        """Check if role has required permission"""
        return required_permission in self.role_permissions.get(user_role, set())
    
    def authorize_plugin(self, user_role: Role, plugin_name: str) -> bool:
        """Check if user role can execute plugin"""
        required_perms = self.plugin_permissions.get(plugin_name, set())
        user_perms = self.role_permissions.get(user_role, set())
        
        # User must have all required permissions
        return required_perms.issubset(user_perms)
    
    def require_permission(self, permission: Permission):
        """Decorator to enforce permission on plugin"""
        def decorator(func):
            @wraps(func)
            def wrapper(user_context, *args, **kwargs):
                if not self.has_permission(user_context.role, permission):
                    raise PermissionError(
                        f"User lacks required permission: {permission.value}"
                    )
                return func(user_context, *args, **kwargs)
            return wrapper
        return decorator

# Usage
auth_manager = PluginAuthorizationManager()

class UserContext:
    """User context with authentication info"""
    def __init__(self, user_id: str, role: Role):
        self.user_id = user_id
        self.role = role

@auth_manager.require_permission(Permission.WRITE_DATA)
def database_write_plugin(user_context: UserContext, 
                         table: str, data: Dict):
    """Plugin with permission enforcement"""
    # Permission already checked by decorator
    return db.insert(table, data)

@auth_manager.require_permission(Permission.READ_FILES)
def file_read_plugin(user_context: UserContext, filepath: str):
    """File read with authorization"""
    # Additional owner check
    file_owner = get_file_owner(filepath)
    if file_owner != user_context.user_id and user_context.role != Role.ADMIN:
        raise PermissionError("Access denied: not file owner")
    
    return read_file(filepath)

# Execute with authorization
user = UserContext("user123", Role.USER)

try:
    # This will succeed (user has READ_FILES permission)
    content = file_read_plugin(user, "/documents/user123/data.txt")
    
    # This will fail (user lacks EXECUTE_COMMAND permission)
    result = system_command_plugin(user, "ls")
    
except PermissionError as e:
    print(f"Authorization failed: {e}")
```

### 2. Plugin Authentication

**Verify plugin caller identity**:

```python
import hmac
import hashlib
import secrets
from typing import Optional

class PluginAuthenticator:
    """Authenticate plugin requests"""
    
    def __init__(self):
        self.api_keys: Dict[str, Dict] = {}
    
    def generate_api_key(self, user_id: str) -> str:
        """Generate secure API key for user"""
        api_key = secrets.token_urlsafe(32)
        
        # Store hashed version
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        self.api_keys[key_hash] = {
            "user_id": user_id,
            "created_at": datetime.now(),
            "active": True
        }
        
        return api_key
    
    def verify_api_key(self, api_key: str) -> Optional[str]:
        """Verify API key and return user ID"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        key_data = self.api_keys.get(key_hash)
        if not key_data or not key_data["active"]:
            return None
        
        return key_data["user_id"]
    
    def generate_signature(self, secret: str, data: str) -> str:
        """Generate HMAC signature for plugin request"""
        return hmac.new(
            secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def verify_signature(self, secret: str, data: str, 
                        signature: str) -> bool:
        """Verify request signature"""
        expected = self.generate_signature(secret, data)
        return hmac.compare_digest(expected, signature)

# Usage
authenticator = PluginAuthenticator()

def authenticated_plugin_execution(api_key: str, plugin_name: str, 
                                  parameters: Dict):
    """Execute plugin with authentication"""
    # Verify API key
    user_id = authenticator.verify_api_key(api_key)
    if not user_id:
        raise AuthenticationError("Invalid API key")
    
    # Get user context
    user = get_user(user_id)
    user_context = UserContext(user_id, user.role)
    
    # Check authorization
    if not auth_manager.authorize_plugin(user_context.role, plugin_name):
        raise PermissionError("Plugin access denied")
    
    # Execute plugin
    return execute_plugin(plugin_name, user_context, parameters)
```

## Secure Plugin Architecture

### 1. Plugin Sandboxing

**Isolate plugin execution in restricted environment**:

```python
import subprocess
import json
from typing import Any, Dict
import tempfile
import os

class PluginSandbox:
    """Execute plugins in sandboxed environment"""
    
    def __init__(self):
        self.timeout = 30
        self.max_memory_mb = 512
        self.allowed_syscalls = ['read', 'write', 'open', 'close']
    
    def execute_sandboxed(self, plugin_code: str, 
                         parameters: Dict) -> Any:
        """Execute plugin in sandbox"""
        # Create temporary directory for plugin
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write plugin code
            plugin_file = os.path.join(tmpdir, "plugin.py")
            with open(plugin_file, 'w') as f:
                f.write(plugin_code)
            
            # Write parameters
            params_file = os.path.join(tmpdir, "params.json")
            with open(params_file, 'w') as f:
                json.dump(parameters, f)
            
            # Execute in sandbox using firejail or similar
            cmd = [
                'firejail',
                '--noprofile',
                '--private=' + tmpdir,
                '--net=none',  # No network access
                '--noroot',  # No root access
                f'--rlimit-as={self.max_memory_mb * 1024 * 1024}',  # Memory limit
                'python3', plugin_file
            ]
            
            try:
                result = subprocess.run(
                    cmd,
                    timeout=self.timeout,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    raise RuntimeError(f"Plugin execution failed: {result.stderr}")
                
                return json.loads(result.stdout)
            
            except subprocess.TimeoutExpired:
                raise TimeoutError("Plugin execution timeout")

# Docker-based sandbox
class DockerPluginSandbox:
    """Execute plugins in Docker container"""
    
    def execute_in_container(self, plugin_name: str, 
                            parameters: Dict) -> Any:
        """Execute plugin in isolated Docker container"""
        import docker
        
        client = docker.from_env()
        
        try:
            # Run container with restrictions
            container = client.containers.run(
                'plugin-runtime:latest',
                command=f'python -c "import plugin_{plugin_name}; print(plugin_{plugin_name}.execute({parameters}))"',
                mem_limit='512m',  # Memory limit
                cpu_quota=50000,  # CPU limit
                network_disabled=True,  # No network
                read_only=True,  # Read-only filesystem
                security_opt=['no-new-privileges'],
                cap_drop=['ALL'],  # Drop all capabilities
                detach=False,
                remove=True,
                timeout=30
            )
            
            return json.loads(container.decode())
        
        except docker.errors.ContainerError as e:
            raise RuntimeError(f"Container execution failed: {e}")
```

### 2. Principle of Least Privilege

**Grant minimum necessary permissions**:

```python
class PluginPermissionManager:
    """Manage granular plugin permissions"""
    
    def __init__(self):
        self.plugin_capabilities = {}
    
    def define_plugin_capabilities(self, plugin_name: str, 
                                  capabilities: Dict):
        """Define what plugin is allowed to do"""
        self.plugin_capabilities[plugin_name] = capabilities
    
    def check_capability(self, plugin_name: str, 
                        action: str, resource: str) -> bool:
        """Check if plugin can perform action on resource"""
        caps = self.plugin_capabilities.get(plugin_name, {})
        
        allowed_actions = caps.get('actions', [])
        allowed_resources = caps.get('resources', [])
        
        if action not in allowed_actions:
            raise PermissionError(f"Plugin cannot perform action: {action}")
        
        if resource not in allowed_resources:
            raise PermissionError(f"Plugin cannot access resource: {resource}")
        
        return True

# Define minimal capabilities
perm_manager = PluginPermissionManager()

perm_manager.define_plugin_capabilities('weather_plugin', {
    'actions': ['http_get'],
    'resources': ['https://api.weather.com/*'],
    'max_requests_per_minute': 10
})

perm_manager.define_plugin_capabilities('database_read', {
    'actions': ['database_select'],
    'resources': ['table:products', 'table:orders'],
    'max_rows': 100
})

# Plugin enforces capabilities
def execute_with_capabilities(plugin_name: str, action: str, 
                             resource: str):
    """Execute only if plugin has capability"""
    perm_manager.check_capability(plugin_name, action, resource)
    
    # Proceed with action
    return perform_action(action, resource)
```

## SSRF Prevention

### 1. URL Allowlist and Validation

**Strictly control URL access**:

```python
from urllib.parse import urlparse
import ipaddress
from typing import List, Set

class SSRFProtection:
    """Prevent Server-Side Request Forgery"""
    
    def __init__(self):
        self.allowed_domains: Set[str] = set()
        self.blocked_ips: Set[str] = {
            '127.0.0.1', '::1', '0.0.0.0',
            '169.254.169.254',  # AWS metadata
            'metadata.google.internal',  # GCP metadata
        }
        self.blocked_ip_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),      # Private
            ipaddress.ip_network('172.16.0.0/12'),   # Private
            ipaddress.ip_network('192.168.0.0/16'),  # Private
            ipaddress.ip_network('127.0.0.0/8'),     # Loopback
            ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ]
    
    def add_allowed_domain(self, domain: str):
        """Add domain to allowlist"""
        self.allowed_domains.add(domain.lower())
    
    def is_safe_url(self, url: str) -> bool:
        """Check if URL is safe to request"""
        try:
            parsed = urlparse(url)
            
            # Only allow HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                raise ValueError(f"Scheme not allowed: {parsed.scheme}")
            
            # Check domain allowlist
            if self.allowed_domains:
                if parsed.hostname not in self.allowed_domains:
                    raise ValueError(f"Domain not in allowlist: {parsed.hostname}")
            
            # Resolve hostname to IP
            import socket
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Check against blocked IPs
            if ip in self.blocked_ips:
                raise ValueError(f"Access to blocked IP: {ip}")
            
            # Check against blocked ranges
            for ip_range in self.blocked_ip_ranges:
                if ip_obj in ip_range:
                    raise ValueError(f"Access to private IP range: {ip}")
            
            return True
        
        except Exception as e:
            raise ValueError(f"URL validation failed: {e}")
    
    def safe_request(self, url: str, method: str = 'GET', 
                    timeout: int = 10):
        """Make HTTP request with SSRF protection"""
        import requests
        
        # Validate URL
        self.is_safe_url(url)
        
        # Make request with restrictions
        response = requests.request(
            method,
            url,
            timeout=timeout,
            allow_redirects=False,  # Prevent redirect-based SSRF
            verify=True,  # Verify SSL
        )
        
        # Check redirect if any
        if response.is_redirect:
            redirect_url = response.headers.get('Location')
            if redirect_url:
                self.is_safe_url(redirect_url)
        
        return response

# Usage
ssrf_protection = SSRFProtection()

# Add allowed domains
ssrf_protection.add_allowed_domain('api.example.com')
ssrf_protection.add_allowed_domain('data.example.com')

def secure_url_fetch_plugin(url: str):
    """URL fetch with SSRF protection"""
    try:
        response = ssrf_protection.safe_request(url)
        return response.text
    except ValueError as e:
        return {"error": f"SSRF protection: {e}"}
```

## Command Injection Prevention

### 1. Safe Command Execution

**Never use shell execution, use safe APIs**:

```python
import subprocess
import shlex
from typing import List

class SafeCommandExecutor:
    """Execute system commands safely"""
    
    def __init__(self):
        self.allowed_commands = {
            'ls': ['-l', '-a', '-h'],
            'cat': [],
            'grep': ['-i', '-n'],
        }
    
    def execute_safe(self, command: str, args: List[str]) -> str:
        """Execute command without shell"""
        # Check command whitelist
        if command not in self.allowed_commands:
            raise ValueError(f"Command not allowed: {command}")
        
        # Validate arguments
        allowed_args = self.allowed_commands[command]
        for arg in args:
            # Check if arg is a flag
            if arg.startswith('-'):
                if arg not in allowed_args:
                    raise ValueError(f"Argument not allowed: {arg}")
            else:
                # Validate file argument
                if not self.is_safe_path(arg):
                    raise ValueError(f"Unsafe path: {arg}")
        
        # Build command list (NO SHELL=TRUE)
        cmd_list = [command] + args
        
        try:
            result = subprocess.run(
                cmd_list,
                shell=False,  # NEVER use shell=True
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
            return result.stdout
        
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Command failed: {e.stderr}")
    
    def is_safe_path(self, path: str) -> bool:
        """Validate path is safe"""
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '>', '<', '$(', '${']
        return not any(char in path for char in dangerous_chars)

# Usage - WRONG WAY (VULNERABLE)
def vulnerable_command_plugin(user_input):
    # NEVER DO THIS
    result = subprocess.run(
        f"ls {user_input}",  # Command injection possible
        shell=True,  # DANGEROUS
        capture_output=True
    )
    return result.stdout

# Usage - RIGHT WAY (SECURE)
executor = SafeCommandExecutor()

def secure_command_plugin(directory: str):
    """Secure command execution"""
    try:
        # Validate input
        if not directory.startswith('/safe/directory/'):
            raise ValueError("Directory not in allowed path")
        
        # Execute without shell
        result = executor.execute_safe('ls', ['-l', directory])
        return result
    
    except (ValueError, RuntimeError) as e:
        return {"error": str(e)}
```

## Path Traversal Prevention

### 1. Secure File Access

**Validate and restrict file paths**:

```python
import os
from pathlib import Path
from typing import Optional

class SecureFileAccess:
    """Secure file operations with path validation"""
    
    def __init__(self, base_directory: str):
        self.base_dir = os.path.abspath(base_directory)
    
    def validate_path(self, filepath: str) -> str:
        """Validate and resolve file path"""
        # Convert to absolute path
        abs_path = os.path.abspath(os.path.join(self.base_dir, filepath))
        
        # Check if path is within base directory
        if not abs_path.startswith(self.base_dir):
            raise ValueError(f"Path traversal detected: {filepath}")
        
        # Additional checks
        if '..' in filepath:
            raise ValueError("Parent directory references not allowed")
        
        if filepath.startswith('/'):
            raise ValueError("Absolute paths not allowed")
        
        # Check for symlinks
        if os.path.islink(abs_path):
            # Resolve symlink and validate
            real_path = os.path.realpath(abs_path)
            if not real_path.startswith(self.base_dir):
                raise ValueError("Symlink outside base directory")
        
        return abs_path
    
    def read_file(self, filepath: str) -> str:
        """Safely read file"""
        safe_path = self.validate_path(filepath)
        
        # Check file exists
        if not os.path.isfile(safe_path):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        # Check size limit
        max_size = 10 * 1024 * 1024  # 10MB
        if os.path.getsize(safe_path) > max_size:
            raise ValueError("File too large")
        
        with open(safe_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def write_file(self, filepath: str, content: str):
        """Safely write file"""
        safe_path = self.validate_path(filepath)
        
        # Create directory if needed
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)
        
        with open(safe_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def list_directory(self, dirpath: str) -> List[str]:
        """Safely list directory"""
        safe_path = self.validate_path(dirpath)
        
        if not os.path.isdir(safe_path):
            raise ValueError(f"Not a directory: {dirpath}")
        
        # List files with relative paths
        files = []
        for item in os.listdir(safe_path):
            rel_path = os.path.relpath(
                os.path.join(safe_path, item),
                self.base_dir
            )
            files.append(rel_path)
        
        return files

# Usage
file_access = SecureFileAccess('/app/user_data')

def secure_file_read_plugin(filepath: str):
    """File read with path validation"""
    try:
        content = file_access.read_file(filepath)
        return {"content": content}
    except (ValueError, FileNotFoundError) as e:
        return {"error": str(e)}

# Example usage
result = secure_file_read_plugin('documents/report.txt')  # OK
result = secure_file_read_plugin('../../../etc/passwd')   # Blocked
result = secure_file_read_plugin('/etc/passwd')           # Blocked
```

## Rate Limiting and Resource Controls

### 1. Request Rate Limiting

**Prevent abuse through rate limiting**:

```python
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict
import time

class RateLimiter:
    """Rate limit plugin invocations"""
    
    def __init__(self):
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.limits = {
            'default': {'requests': 100, 'window': 60},  # 100 req/min
            'database': {'requests': 50, 'window': 60},
            'api_call': {'requests': 20, 'window': 60},
            'file_operation': {'requests': 30, 'window': 60},
        }
    
    def is_allowed(self, user_id: str, plugin_name: str) -> bool:
        """Check if request is within rate limit"""
        key = f"{user_id}:{plugin_name}"
        now = time.time()
        
        # Get limit for plugin
        limit_config = self.limits.get(plugin_name, self.limits['default'])
        max_requests = limit_config['requests']
        window_seconds = limit_config['window']
        
        # Clean old requests
        cutoff = now - window_seconds
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if req_time > cutoff
        ]
        
        # Check limit
        if len(self.requests[key]) >= max_requests:
            return False
        
        # Record request
        self.requests[key].append(now)
        return True
    
    def get_retry_after(self, user_id: str, plugin_name: str) -> int:
        """Get seconds until rate limit resets"""
        key = f"{user_id}:{plugin_name}"
        if not self.requests[key]:
            return 0
        
        limit_config = self.limits.get(plugin_name, self.limits['default'])
        oldest_request = min(self.requests[key])
        window_seconds = limit_config['window']
        
        reset_time = oldest_request + window_seconds
        return max(0, int(reset_time - time.time()))

# Resource limits
class ResourceLimiter:
    """Limit resource consumption"""
    
    def __init__(self):
        self.limits = {
            'max_response_size': 1024 * 1024,  # 1MB
            'max_execution_time': 30,  # seconds
            'max_memory': 512 * 1024 * 1024,  # 512MB
        }
    
    def limit_execution_time(self, timeout: int):
        """Decorator to limit execution time"""
        import signal
        
        def decorator(func):
            def wrapper(*args, **kwargs):
                def timeout_handler(signum, frame):
                    raise TimeoutError("Plugin execution timeout")
                
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout)
                
                try:
                    result = func(*args, **kwargs)
                finally:
                    signal.alarm(0)
                
                return result
            return wrapper
        return decorator
    
    def limit_response_size(self, response: Any) -> Any:
        """Limit response size"""
        import sys
        
        size = sys.getsizeof(response)
        if size > self.limits['max_response_size']:
            raise ValueError(f"Response too large: {size} bytes")
        
        return response

# Usage
rate_limiter = RateLimiter()
resource_limiter = ResourceLimiter()

def execute_plugin_with_limits(user_id: str, plugin_name: str, 
                               parameters: Dict):
    """Execute plugin with rate and resource limits"""
    # Check rate limit
    if not rate_limiter.is_allowed(user_id, plugin_name):
        retry_after = rate_limiter.get_retry_after(user_id, plugin_name)
        raise TooManyRequestsError(
            f"Rate limit exceeded. Retry after {retry_after}s"
        )
    
    # Execute with timeout
    @resource_limiter.limit_execution_time(30)
    def execute():
        return plugins[plugin_name](**parameters)
    
    try:
        result = execute()
        
        # Limit response size
        return resource_limiter.limit_response_size(result)
    
    except TimeoutError:
        return {"error": "Plugin execution timeout"}
    except ValueError as e:
        return {"error": str(e)}
```

## Monitoring and Logging

### 1. Comprehensive Plugin Logging

**Log all plugin activities for security monitoring**:

```python
import logging
import json
from datetime import datetime
from typing import Any, Dict

class PluginAuditLogger:
    """Audit logging for plugin executions"""
    
    def __init__(self):
        self.logger = logging.getLogger('plugin_audit')
        self.logger.setLevel(logging.INFO)
        
        # JSON formatter for structured logging
        handler = logging.FileHandler('plugin_audit.log')
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)
    
    def log_execution(self, user_id: str, plugin_name: str,
                     parameters: Dict, result: Any, 
                     execution_time: float, success: bool):
        """Log plugin execution"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'plugin_name': plugin_name,
            'parameters': parameters,
            'success': success,
            'execution_time_ms': execution_time * 1000,
            'result_size': len(str(result)),
        }
        
        if not success:
            log_entry['error'] = str(result)
        
        self.logger.info(json.dumps(log_entry))
    
    def log_security_event(self, event_type: str, details: Dict):
        """Log security-relevant events"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'severity': 'HIGH',
            'details': details
        }
        
        self.logger.warning(json.dumps(log_entry))

# Anomaly detection
class PluginAnomalyDetector:
    """Detect suspicious plugin usage patterns"""
    
    def __init__(self):
        self.user_patterns = defaultdict(list)
        self.alert_thresholds = {
            'failed_attempts': 5,
            'unusual_parameters': 3,
            'rapid_requests': 10,
        }
    
    def check_for_anomalies(self, user_id: str, plugin_name: str,
                           parameters: Dict, success: bool):
        """Detect anomalous behavior"""
        # Track failed attempts
        if not success:
            failed_key = f"{user_id}:failed"
            self.user_patterns[failed_key].append(time.time())
            
            recent_failures = [
                t for t in self.user_patterns[failed_key]
                if time.time() - t < 300  # Last 5 minutes
            ]
            
            if len(recent_failures) > self.alert_thresholds['failed_attempts']:
                return {
                    'anomaly_type': 'excessive_failures',
                    'details': f'{len(recent_failures)} failures in 5 minutes'
                }
        
        # Check for SQL injection patterns
        param_str = json.dumps(parameters).lower()
        injection_patterns = [
            'union select', 'or 1=1', '--', '; drop',
            '../', '../../', '/etc/passwd'
        ]
        
        if any(pattern in param_str for pattern in injection_patterns):
            return {
                'anomaly_type': 'injection_attempt',
                'details': f'Suspicious patterns in parameters'
            }
        
        return None

# Usage
audit_logger = PluginAuditLogger()
anomaly_detector = PluginAnomalyDetector()

def monitored_plugin_execution(user_id: str, plugin_name: str,
                               parameters: Dict):
    """Execute plugin with monitoring"""
    start_time = time.time()
    success = False
    result = None
    
    try:
        # Execute plugin
        result = execute_plugin(plugin_name, parameters)
        success = True
        
    except Exception as e:
        result = {"error": str(e)}
        
    finally:
        execution_time = time.time() - start_time
        
        # Log execution
        audit_logger.log_execution(
            user_id, plugin_name, parameters,
            result, execution_time, success
        )
        
        # Check for anomalies
        anomaly = anomaly_detector.check_for_anomalies(
            user_id, plugin_name, parameters, success
        )
        
        if anomaly:
            audit_logger.log_security_event('anomaly_detected', {
                'user_id': user_id,
                'plugin_name': plugin_name,
                'anomaly': anomaly
            })
    
    return result
```

## Best Practices

### Plugin Development
- ✅ Validate ALL inputs before use
- ✅ Use parameterized queries for databases
- ✅ Never use `shell=True` in subprocess
- ✅ Implement proper error handling
- ✅ Use principle of least privilege
- ✅ Apply defense in depth

### Security Controls
- ✅ Implement authentication and authorization
- ✅ Use allowlists for URLs, domains, commands
- ✅ Sandbox plugin execution
- ✅ Apply rate limiting
- ✅ Monitor and log all activities
- ✅ Regular security audits

### Architecture
- ✅ Isolate plugins from core system
- ✅ Use containers or VMs for execution
- ✅ Implement circuit breakers
- ✅ Use secure communication channels
- ✅ Version control plugin code
- ✅ Maintain plugin inventory

### Operations
- ✅ Monitor for suspicious patterns
- ✅ Alert on anomalies
- ✅ Regular penetration testing
- ✅ Incident response plan
- ✅ Keep dependencies updated
- ✅ Security training for developers

---

**Key Principle**: Treat plugins as untrusted code running in a hostile environment. Validate, authorize, sandbox, limit, and monitor every aspect of plugin execution.
