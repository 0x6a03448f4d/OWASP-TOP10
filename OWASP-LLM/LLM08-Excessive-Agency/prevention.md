# LLM08: Excessive Agency - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Least Privilege Implementation](#least-privilege-implementation)
- [Human-in-the-Loop Controls](#human-in-the-loop-controls)
- [Rate Limiting and Boundaries](#rate-limiting-and-boundaries)
- [Action Validation](#action-validation)
- [Monitoring and Observability](#monitoring-and-observability)
- [Secure Agent Architecture](#secure-agent-architecture)
- [Best Practices](#best-practices)

## Prevention Strategy Overview

Preventing excessive agency requires implementing multiple layers of control over AI agent autonomy, permissions, and actions.

### Defense-in-Depth Layers

```
[Permission Scoping] → [Action Validation] → [Approval Workflows]
        ↓                     ↓                      ↓
   Minimal rights        Verify before          Human review
   granted               execution              for critical ops
        ↓                     ↓                      ↓
[Rate Limiting] → [Monitoring] → [Rollback Capability]
        ↓              ↓                 ↓
   Prevent abuse   Detect anomalies   Undo mistakes
```

## Least Privilege Implementation

### 1. Permission Scoping

**Grant only necessary permissions**:

```python
from typing import List, Set, Optional
from enum import Enum

class Permission(Enum):
    """Define granular permissions"""
    READ_DATA = "read_data"
    WRITE_DATA = "write_data"
    DELETE_DATA = "delete_data"
    EXECUTE_CODE = "execute_code"
    SEND_EMAIL = "send_email"
    MAKE_PAYMENT = "make_payment"
    MODIFY_CONFIG = "modify_config"

class PermissionScope:
    """Define permission boundaries"""
    def __init__(self, 
                 allowed_permissions: Set[Permission],
                 allowed_resources: List[str],
                 max_impact: str = 'low'):
        self.allowed_permissions = allowed_permissions
        self.allowed_resources = allowed_resources
        self.max_impact = max_impact  # low, medium, high
    
    def can_perform(self, permission: Permission, resource: str) -> bool:
        """Check if action is allowed"""
        # Check permission
        if permission not in self.allowed_permissions:
            return False
        
        # Check resource scope
        if resource not in self.allowed_resources:
            return False
        
        return True

class SecureAgent:
    """Agent with scoped permissions"""
    
    def __init__(self, name: str, permission_scope: PermissionScope):
        self.name = name
        self.permissions = permission_scope
    
    def execute_action(self, action: str, permission: Permission, 
                      resource: str) -> Optional[str]:
        """Execute action only if permitted"""
        # Verify permission
        if not self.permissions.can_perform(permission, resource):
            return f"❌ Permission denied: {permission.value} on {resource}"
        
        # Execute action
        return f"✅ Executed: {action}"

# Usage - Read-only customer service agent
cs_agent = SecureAgent(
    name="CustomerServiceAgent",
    permission_scope=PermissionScope(
        allowed_permissions={Permission.READ_DATA},  # Only read
        allowed_resources=['customer_profiles', 'order_history'],  # Specific tables
        max_impact='low'
    )
)

# This succeeds
result = cs_agent.execute_action(
    action="SELECT * FROM customer_profiles WHERE id=123",
    permission=Permission.READ_DATA,
    resource='customer_profiles'
)
print(result)  # ✅ Executed

# This fails - no write permission
result = cs_agent.execute_action(
    action="UPDATE customer_profiles SET status='premium'",
    permission=Permission.WRITE_DATA,
    resource='customer_profiles'
)
print(result)  # ❌ Permission denied

# This fails - resource not in scope
result = cs_agent.execute_action(
    action="SELECT * FROM admin_credentials",
    permission=Permission.READ_DATA,
    resource='admin_credentials'
)
print(result)  # ❌ Permission denied
```

### 2. Role-Based Access Control

**Implement RBAC for AI agents**:

```python
from dataclasses import dataclass
from typing import Set, Dict

@dataclass
class AgentRole:
    """Define agent role with specific permissions"""
    name: str
    permissions: Set[Permission]
    resource_patterns: List[str]
    max_actions_per_hour: int
    requires_approval_for: Set[Permission]

class AgentRoleManager:
    """Manage agent roles and permissions"""
    
    def __init__(self):
        self.roles = self._define_roles()
    
    def _define_roles(self) -> Dict[str, AgentRole]:
        """Define standard agent roles"""
        return {
            'viewer': AgentRole(
                name='viewer',
                permissions={Permission.READ_DATA},
                resource_patterns=['public_*', 'customer_profiles'],
                max_actions_per_hour=1000,
                requires_approval_for=set()
            ),
            'customer_service': AgentRole(
                name='customer_service',
                permissions={
                    Permission.READ_DATA,
                    Permission.WRITE_DATA,
                    Permission.SEND_EMAIL
                },
                resource_patterns=[
                    'customer_*', 
                    'orders',
                    'tickets'
                ],
                max_actions_per_hour=500,
                requires_approval_for={Permission.SEND_EMAIL}  # Email needs approval
            ),
            'analyst': AgentRole(
                name='analyst',
                permissions={Permission.READ_DATA},
                resource_patterns=['*'],  # Can read all
                max_actions_per_hour=100,
                requires_approval_for=set()
            ),
            'admin': AgentRole(
                name='admin',
                permissions={
                    Permission.READ_DATA,
                    Permission.WRITE_DATA,
                    Permission.DELETE_DATA,
                    Permission.MODIFY_CONFIG
                },
                resource_patterns=['*'],
                max_actions_per_hour=50,
                requires_approval_for={  # Critical actions need approval
                    Permission.DELETE_DATA,
                    Permission.MODIFY_CONFIG
                }
            )
        }
    
    def get_role(self, role_name: str) -> Optional[AgentRole]:
        """Get role definition"""
        return self.roles.get(role_name)
    
    def validate_action(self, role: AgentRole, permission: Permission,
                       resource: str) -> tuple[bool, str]:
        """Validate if role can perform action"""
        # Check permission
        if permission not in role.permissions:
            return False, f"Role {role.name} lacks {permission.value} permission"
        
        # Check resource pattern
        import fnmatch
        resource_allowed = any(
            fnmatch.fnmatch(resource, pattern)
            for pattern in role.resource_patterns
        )
        
        if not resource_allowed:
            return False, f"Resource {resource} not accessible to {role.name}"
        
        return True, "Action allowed"

# Usage
role_manager = AgentRoleManager()

# Create customer service agent with limited role
cs_role = role_manager.get_role('customer_service')

# Validate actions
allowed, msg = role_manager.validate_action(
    role=cs_role,
    permission=Permission.READ_DATA,
    resource='customer_profiles'
)
print(f"Read customer: {allowed} - {msg}")  # ✅ Allowed

allowed, msg = role_manager.validate_action(
    role=cs_role,
    permission=Permission.DELETE_DATA,
    resource='customer_profiles'
)
print(f"Delete customer: {allowed} - {msg}")  # ❌ Denied
```

### 3. Temporary Elevated Access

**Grant temporary permissions when needed**:

```python
import time
from datetime import datetime, timedelta

class TemporaryPermission:
    """Grant time-limited elevated permissions"""
    
    def __init__(self, permission: Permission, duration_minutes: int,
                 granted_by: str, justification: str):
        self.permission = permission
        self.granted_at = datetime.now()
        self.expires_at = self.granted_at + timedelta(minutes=duration_minutes)
        self.granted_by = granted_by
        self.justification = justification
        self.revoked = False
    
    def is_valid(self) -> bool:
        """Check if permission is still valid"""
        if self.revoked:
            return False
        return datetime.now() < self.expires_at
    
    def revoke(self):
        """Revoke permission before expiration"""
        self.revoked = True

class PermissionManager:
    """Manage temporary permission elevation"""
    
    def __init__(self):
        self.temp_permissions: Dict[str, List[TemporaryPermission]] = {}
    
    def grant_temporary_permission(self, agent_id: str,
                                   permission: Permission,
                                   duration_minutes: int,
                                   granted_by: str,
                                   justification: str) -> TemporaryPermission:
        """Grant temporary elevated permission"""
        temp_perm = TemporaryPermission(
            permission=permission,
            duration_minutes=duration_minutes,
            granted_by=granted_by,
            justification=justification
        )
        
        if agent_id not in self.temp_permissions:
            self.temp_permissions[agent_id] = []
        
        self.temp_permissions[agent_id].append(temp_perm)
        
        print(f"✅ Granted {permission.value} to {agent_id} for {duration_minutes}min")
        print(f"   Justification: {justification}")
        print(f"   Expires: {temp_perm.expires_at}")
        
        return temp_perm
    
    def has_permission(self, agent_id: str, permission: Permission) -> bool:
        """Check if agent has permission (including temporary)"""
        if agent_id not in self.temp_permissions:
            return False
        
        # Check valid temporary permissions
        for temp_perm in self.temp_permissions[agent_id]:
            if temp_perm.permission == permission and temp_perm.is_valid():
                return True
        
        return False
    
    def cleanup_expired(self):
        """Remove expired permissions"""
        for agent_id in self.temp_permissions:
            self.temp_permissions[agent_id] = [
                p for p in self.temp_permissions[agent_id] 
                if p.is_valid()
            ]

# Usage
perm_manager = PermissionManager()

# Grant temporary delete permission
temp_perm = perm_manager.grant_temporary_permission(
    agent_id='agent_001',
    permission=Permission.DELETE_DATA,
    duration_minutes=30,
    granted_by='admin@company.com',
    justification='Emergency cleanup of corrupted records'
)

# Check permission
if perm_manager.has_permission('agent_001', Permission.DELETE_DATA):
    print("Agent can delete data (temporarily)")

# Revoke early if needed
temp_perm.revoke()
print("Permission revoked")
```

## Human-in-the-Loop Controls

### 1. Approval Workflows

**Require human approval for high-risk actions**:

```python
from enum import Enum
from typing import Callable, Optional
import asyncio

class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"

class ApprovalRequest:
    """Request human approval for action"""
    
    def __init__(self, agent_id: str, action: str,
                 risk_level: str, details: dict):
        self.id = f"approval_{int(time.time())}"
        self.agent_id = agent_id
        self.action = action
        self.risk_level = risk_level
        self.details = details
        self.status = ApprovalStatus.PENDING
        self.created_at = datetime.now()
        self.expires_at = self.created_at + timedelta(minutes=30)
        self.approver = None
        self.decision_reason = None
    
    def approve(self, approver: str, reason: str):
        """Approve the action"""
        self.status = ApprovalStatus.APPROVED
        self.approver = approver
        self.decision_reason = reason
    
    def reject(self, approver: str, reason: str):
        """Reject the action"""
        self.status = ApprovalStatus.REJECTED
        self.approver = approver
        self.decision_reason = reason
    
    def is_expired(self) -> bool:
        """Check if approval request expired"""
        if datetime.now() > self.expires_at:
            self.status = ApprovalStatus.EXPIRED
            return True
        return False

class ApprovalWorkflow:
    """Manage approval workflows for AI actions"""
    
    def __init__(self):
        self.pending_requests: Dict[str, ApprovalRequest] = {}
        self.approval_rules = self._define_approval_rules()
    
    def _define_approval_rules(self) -> Dict[str, Set[Permission]]:
        """Define which actions require approval"""
        return {
            'always': {
                Permission.DELETE_DATA,
                Permission.MAKE_PAYMENT,
                Permission.EXECUTE_CODE
            },
            'high_value': {
                Permission.WRITE_DATA,  # If high impact
                Permission.MODIFY_CONFIG
            },
            'never': {
                Permission.READ_DATA  # Read operations don't need approval
            }
        }
    
    def requires_approval(self, permission: Permission, 
                         impact: str = 'low') -> bool:
        """Check if action requires approval"""
        if permission in self.approval_rules['always']:
            return True
        
        if permission in self.approval_rules['high_value'] and impact in ['medium', 'high']:
            return True
        
        return False
    
    def request_approval(self, agent_id: str, action: str,
                        permission: Permission, details: dict,
                        risk_level: str = 'high') -> ApprovalRequest:
        """Create approval request"""
        request = ApprovalRequest(
            agent_id=agent_id,
            action=action,
            risk_level=risk_level,
            details=details
        )
        
        self.pending_requests[request.id] = request
        
        # Notify approvers
        self._notify_approvers(request)
        
        return request
    
    def _notify_approvers(self, request: ApprovalRequest):
        """Notify human approvers"""
        print("\n" + "="*60)
        print("⚠️  APPROVAL REQUIRED")
        print("="*60)
        print(f"Request ID: {request.id}")
        print(f"Agent: {request.agent_id}")
        print(f"Action: {request.action}")
        print(f"Risk Level: {request.risk_level}")
        print(f"Details:")
        for key, value in request.details.items():
            print(f"  - {key}: {value}")
        print(f"Expires: {request.expires_at}")
        print("="*60 + "\n")
    
    def wait_for_approval(self, request_id: str, 
                         timeout_seconds: int = 1800) -> bool:
        """Wait for human approval (blocking)"""
        request = self.pending_requests.get(request_id)
        if not request:
            return False
        
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            # Check for expiration
            if request.is_expired():
                print(f"❌ Approval request {request_id} expired")
                return False
            
            # Check status
            if request.status == ApprovalStatus.APPROVED:
                print(f"✅ Action approved by {request.approver}")
                print(f"   Reason: {request.decision_reason}")
                return True
            
            if request.status == ApprovalStatus.REJECTED:
                print(f"❌ Action rejected by {request.approver}")
                print(f"   Reason: {request.decision_reason}")
                return False
            
            # Wait before checking again
            time.sleep(1)
        
        print(f"❌ Approval timeout for {request_id}")
        return False
    
    def process_approval(self, request_id: str, approved: bool,
                        approver: str, reason: str):
        """Process approval decision"""
        request = self.pending_requests.get(request_id)
        if not request:
            return
        
        if approved:
            request.approve(approver, reason)
        else:
            request.reject(approver, reason)

# Usage with agent actions
class ApprovalControlledAgent:
    """Agent that requires approval for risky actions"""
    
    def __init__(self, agent_id: str, approval_workflow: ApprovalWorkflow):
        self.agent_id = agent_id
        self.approval_workflow = approval_workflow
    
    def execute_with_approval(self, action: str, permission: Permission,
                             details: dict, risk_level: str = 'high'):
        """Execute action with approval if needed"""
        # Check if approval needed
        if self.approval_workflow.requires_approval(permission, risk_level):
            print(f"🔒 Action requires approval: {action}")
            
            # Request approval
            request = self.approval_workflow.request_approval(
                agent_id=self.agent_id,
                action=action,
                permission=permission,
                details=details,
                risk_level=risk_level
            )
            
            # Wait for approval
            approved = self.approval_workflow.wait_for_approval(request.id)
            
            if not approved:
                return "❌ Action cancelled - approval not granted"
        
        # Execute action
        print(f"✅ Executing: {action}")
        return self._execute_action(action, details)
    
    def _execute_action(self, action: str, details: dict):
        """Actually execute the action"""
        # Implementation of actual action
        return f"Action executed: {action}"

# Example usage
workflow = ApprovalWorkflow()
agent = ApprovalControlledAgent('delete_agent', workflow)

# High-risk action requires approval
result = agent.execute_with_approval(
    action="DELETE FROM customers WHERE inactive=true",
    permission=Permission.DELETE_DATA,
    details={
        'table': 'customers',
        'estimated_rows': 5000,
        'condition': 'inactive=true'
    },
    risk_level='high'
)

# Simulate approval (in real system, human would approve via UI)
workflow.process_approval(
    request_id=list(workflow.pending_requests.keys())[0],
    approved=True,
    approver='admin@company.com',
    reason='Confirmed these are test accounts'
)
```

### 2. Dry-Run Mode

**Preview actions before execution**:

```python
class DryRunAgent:
    """Agent with dry-run capability"""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.dry_run_mode = True  # Default to safe mode
    
    def execute_action(self, action: str, parameters: dict):
        """Execute action with dry-run option"""
        if self.dry_run_mode:
            return self._dry_run(action, parameters)
        else:
            return self._execute(action, parameters)
    
    def _dry_run(self, action: str, parameters: dict) -> dict:
        """Simulate action and return preview"""
        preview = {
            'action': action,
            'parameters': parameters,
            'estimated_impact': self._estimate_impact(action, parameters),
            'affected_resources': self._identify_affected_resources(action, parameters),
            'reversible': self._is_reversible(action),
            'risk_level': self._assess_risk(action, parameters)
        }
        
        print("\n🔍 DRY RUN - Action Preview:")
        print(f"Action: {preview['action']}")
        print(f"Estimated Impact: {preview['estimated_impact']}")
        print(f"Affected Resources: {preview['affected_resources']}")
        print(f"Reversible: {preview['reversible']}")
        print(f"Risk Level: {preview['risk_level']}")
        print("\nNo actual changes made (dry-run mode)")
        
        return preview
    
    def _execute(self, action: str, parameters: dict):
        """Actually execute the action"""
        print(f"✅ Executing: {action}")
        # Real execution here
        return {'status': 'executed'}
    
    def _estimate_impact(self, action: str, parameters: dict) -> str:
        """Estimate impact of action"""
        if 'DELETE' in action.upper():
            return f"Will delete approximately {parameters.get('row_count', 'unknown')} rows"
        elif 'UPDATE' in action.upper():
            return f"Will modify approximately {parameters.get('row_count', 'unknown')} rows"
        return "Read-only operation"
    
    def _identify_affected_resources(self, action: str, parameters: dict) -> List[str]:
        """Identify what will be affected"""
        return parameters.get('tables', [])
    
    def _is_reversible(self, action: str) -> bool:
        """Check if action can be undone"""
        irreversible_keywords = ['DELETE', 'DROP', 'TRUNCATE']
        return not any(kw in action.upper() for kw in irreversible_keywords)
    
    def _assess_risk(self, action: str, parameters: dict) -> str:
        """Assess risk level"""
        if not self._is_reversible(action):
            return 'HIGH'
        elif 'UPDATE' in action.upper():
            return 'MEDIUM'
        return 'LOW'
    
    def enable_execution(self):
        """Enable actual execution after dry-run review"""
        self.dry_run_mode = False
        print("⚠️  Dry-run mode disabled - actions will be executed")
    
    def enable_dry_run(self):
        """Re-enable dry-run mode"""
        self.dry_run_mode = True
        print("✅ Dry-run mode enabled - actions will be previewed only")

# Usage
agent = DryRunAgent('maintenance_agent')

# First, preview the action
preview = agent.execute_action(
    action="DELETE FROM old_logs WHERE created_at < NOW() - INTERVAL 90 DAY",
    parameters={
        'tables': ['old_logs'],
        'row_count': 50000
    }
)

# Review preview, then enable execution if approved
if preview['risk_level'] == 'HIGH':
    print("\n⚠️  High risk action - requires approval")
    # ... get approval ...
    
# Only then enable actual execution
agent.enable_execution()
result = agent.execute_action(
    action="DELETE FROM old_logs WHERE created_at < NOW() - INTERVAL 90 DAY",
    parameters={
        'tables': ['old_logs'],
        'row_count': 50000
    }
)
```

## Rate Limiting and Boundaries

### 1. Action Rate Limiting

**Prevent excessive action execution**:

```python
from collections import deque
import threading

class RateLimiter:
    """Rate limit agent actions"""
    
    def __init__(self, max_actions_per_minute: int,
                 max_actions_per_hour: int):
        self.max_per_minute = max_actions_per_minute
        self.max_per_hour = max_actions_per_hour
        
        self.minute_window = deque(maxlen=max_actions_per_minute)
        self.hour_window = deque(maxlen=max_actions_per_hour)
        
        self.lock = threading.Lock()
    
    def check_and_record(self) -> tuple[bool, str]:
        """Check if action is allowed and record it"""
        with self.lock:
            current_time = time.time()
            
            # Clean old entries from windows
            self._clean_window(self.minute_window, current_time, 60)
            self._clean_window(self.hour_window, current_time, 3600)
            
            # Check minute limit
            if len(self.minute_window) >= self.max_per_minute:
                return False, f"Rate limit exceeded: {self.max_per_minute} actions/minute"
            
            # Check hour limit
            if len(self.hour_window) >= self.max_per_hour:
                return False, f"Rate limit exceeded: {self.max_per_hour} actions/hour"
            
            # Record action
            self.minute_window.append(current_time)
            self.hour_window.append(current_time)
            
            return True, "Action allowed"
    
    def _clean_window(self, window: deque, current_time: float, 
                     window_seconds: int):
        """Remove entries outside time window"""
        while window and current_time - window[0] > window_seconds:
            window.popleft()
    
    def get_stats(self) -> dict:
        """Get current rate limit statistics"""
        current_time = time.time()
        
        self._clean_window(self.minute_window, current_time, 60)
        self._clean_window(self.hour_window, current_time, 3600)
        
        return {
            'actions_last_minute': len(self.minute_window),
            'limit_per_minute': self.max_per_minute,
            'actions_last_hour': len(self.hour_window),
            'limit_per_hour': self.max_per_hour
        }

class RateLimitedAgent:
    """Agent with rate limiting"""
    
    def __init__(self, agent_id: str, rate_limiter: RateLimiter):
        self.agent_id = agent_id
        self.rate_limiter = rate_limiter
    
    def execute_action(self, action: str):
        """Execute action with rate limiting"""
        # Check rate limit
        allowed, message = self.rate_limiter.check_and_record()
        
        if not allowed:
            print(f"❌ {message}")
            return None
        
        # Execute action
        print(f"✅ Executing: {action}")
        return self._do_action(action)
    
    def _do_action(self, action: str):
        """Actually perform the action"""
        return f"Executed: {action}"

# Usage
limiter = RateLimiter(
    max_actions_per_minute=10,
    max_actions_per_hour=100
)

agent = RateLimitedAgent('api_agent', limiter)

# These succeed
for i in range(5):
    agent.execute_action(f"API call {i}")

# Check stats
stats = limiter.get_stats()
print(f"\nRate limit stats: {stats}")

# Try to exceed limit
for i in range(20):
    agent.execute_action(f"Rapid call {i}")
# Last 15 will be rate limited
```

### 2. Recursion Depth Limiting

**Prevent infinite recursion**:

```python
class RecursionLimiter:
    """Limit recursion depth for agents"""
    
    def __init__(self, max_depth: int):
        self.max_depth = max_depth
        self.current_depth = 0
        self.call_stack = []
    
    def enter_recursive_call(self, function_name: str) -> bool:
        """Enter recursive call, return False if limit exceeded"""
        self.current_depth += 1
        self.call_stack.append(function_name)
        
        if self.current_depth > self.max_depth:
            print(f"❌ Recursion depth limit exceeded: {self.max_depth}")
            print(f"Call stack: {' -> '.join(self.call_stack)}")
            return False
        
        return True
    
    def exit_recursive_call(self):
        """Exit recursive call"""
        if self.call_stack:
            self.call_stack.pop()
        self.current_depth = max(0, self.current_depth - 1)
    
    def get_depth(self) -> int:
        """Get current recursion depth"""
        return self.current_depth

class RecursionLimitedAgent:
    """Agent with recursion depth limiting"""
    
    def __init__(self, max_recursion_depth: int = 5):
        self.recursion_limiter = RecursionLimiter(max_recursion_depth)
    
    def research_topic(self, topic: str, depth: int = 0) -> dict:
        """Research topic with recursion limiting"""
        # Check recursion limit
        if not self.recursion_limiter.enter_recursive_call('research_topic'):
            return {'error': 'Max recursion depth exceeded'}
        
        try:
            print(f"{'  ' * depth}Researching: {topic} (depth: {depth})")
            
            # Simulate finding subtopics
            subtopics = self._find_subtopics(topic)
            
            results = {'topic': topic, 'subtopics': []}
            
            # Recursively research subtopics
            for subtopic in subtopics:
                sub_result = self.research_topic(subtopic, depth + 1)
                if 'error' not in sub_result:
                    results['subtopics'].append(sub_result)
                else:
                    print(f"{'  ' * depth}Stopped at depth limit")
                    break
            
            return results
        
        finally:
            # Always exit recursion level
            self.recursion_limiter.exit_recursive_call()
    
    def _find_subtopics(self, topic: str) -> List[str]:
        """Simulate finding subtopics"""
        return [f"{topic}_sub1", f"{topic}_sub2"]

# Usage
agent = RecursionLimitedAgent(max_recursion_depth=3)

# This will be limited at depth 3
result = agent.research_topic("AI Safety")
```

### 3. Cost and Resource Limits

**Limit resource consumption**:

```python
class ResourceLimiter:
    """Limit resource consumption by agents"""
    
    def __init__(self, 
                 max_api_calls: int,
                 max_cost_dollars: float,
                 max_storage_mb: float):
        self.max_api_calls = max_api_calls
        self.max_cost = max_cost_dollars
        self.max_storage = max_storage_mb
        
        self.api_calls_used = 0
        self.cost_incurred = 0.0
        self.storage_used = 0.0
    
    def check_api_call(self, cost_per_call: float = 0.01) -> tuple[bool, str]:
        """Check if API call is within limits"""
        if self.api_calls_used >= self.max_api_calls:
            return False, f"API call limit reached: {self.max_api_calls}"
        
        if self.cost_incurred + cost_per_call > self.max_cost:
            return False, f"Cost limit reached: ${self.max_cost}"
        
        # Record usage
        self.api_calls_used += 1
        self.cost_incurred += cost_per_call
        
        return True, "Within limits"
    
    def check_storage(self, size_mb: float) -> tuple[bool, str]:
        """Check if storage operation is within limits"""
        if self.storage_used + size_mb > self.max_storage:
            return False, f"Storage limit reached: {self.max_storage}MB"
        
        self.storage_used += size_mb
        return True, "Within limits"
    
    def get_usage(self) -> dict:
        """Get current resource usage"""
        return {
            'api_calls': f"{self.api_calls_used}/{self.max_api_calls}",
            'cost': f"${self.cost_incurred:.2f}/${self.max_cost}",
            'storage': f"{self.storage_used:.2f}/{self.max_storage}MB"
        }

class ResourceLimitedAgent:
    """Agent with resource limits"""
    
    def __init__(self, resource_limiter: ResourceLimiter):
        self.resource_limiter = resource_limiter
    
    def make_api_call(self, endpoint: str, cost: float = 0.01):
        """Make API call with resource checking"""
        allowed, message = self.resource_limiter.check_api_call(cost)
        
        if not allowed:
            print(f"❌ {message}")
            return None
        
        print(f"✅ API call to {endpoint} (${cost})")
        return {'data': 'result'}
    
    def store_data(self, data: str, size_mb: float):
        """Store data with size checking"""
        allowed, message = self.resource_limiter.check_storage(size_mb)
        
        if not allowed:
            print(f"❌ {message}")
            return False
        
        print(f"✅ Stored {size_mb}MB of data")
        return True

# Usage
limiter = ResourceLimiter(
    max_api_calls=100,
    max_cost_dollars=10.0,
    max_storage_mb=1000.0
)

agent = ResourceLimitedAgent(limiter)

# These succeed
for i in range(5):
    agent.make_api_call(f"endpoint_{i}", cost=0.50)

# Check usage
print(limiter.get_usage())

# This might hit limits
for i in range(100):
    agent.make_api_call(f"excessive_{i}", cost=0.50)
```

## Action Validation

### 1. Pre-Execution Validation

**Validate actions before execution**:

```python
from typing import Callable

class ActionValidator:
    """Validate actions before execution"""
    
    def __init__(self):
        self.validation_rules = self._define_rules()
    
    def _define_rules(self) -> Dict[str, Callable]:
        """Define validation rules for different action types"""
        return {
            'database_delete': self._validate_delete,
            'file_operation': self._validate_file_op,
            'api_call': self._validate_api_call,
            'payment': self._validate_payment,
        }
    
    def validate(self, action_type: str, parameters: dict) -> tuple[bool, str]:
        """Validate action"""
        validator = self.validation_rules.get(action_type)
        
        if not validator:
            return False, f"Unknown action type: {action_type}"
        
        return validator(parameters)
    
    def _validate_delete(self, parameters: dict) -> tuple[bool, str]:
        """Validate delete operations"""
        # Require WHERE clause
        if 'where_clause' not in parameters or not parameters['where_clause']:
            return False, "DELETE without WHERE clause not allowed"
        
        # Prevent DELETE * or DELETE without specific conditions
        if parameters['where_clause'].strip() == '1=1':
            return False, "DELETE with always-true condition not allowed"
        
        # Require estimated row count
        if 'estimated_rows' not in parameters:
            return False, "Must provide estimated rows to delete"
        
        # Limit bulk deletes
        if parameters['estimated_rows'] > 10000:
            return False, f"Bulk delete limit exceeded: {parameters['estimated_rows']} > 10000"
        
        return True, "Delete validation passed"
    
    def _validate_file_op(self, parameters: dict) -> tuple[bool, str]:
        """Validate file operations"""
        path = parameters.get('path', '')
        
        # Prevent operations on system directories
        forbidden_paths = ['/etc', '/sys', '/boot', '/root']
        if any(path.startswith(forbidden) for forbidden in forbidden_paths):
            return False, f"Operations on system directories not allowed: {path}"
        
        # Require explicit path (no wildcards for deletes)
        if parameters.get('operation') == 'delete' and '*' in path:
            return False, "Wildcard deletes not allowed"
        
        return True, "File operation validation passed"
    
    def _validate_api_call(self, parameters: dict) -> tuple[bool, str]:
        """Validate API calls"""
        # Check endpoint whitelist
        endpoint = parameters.get('endpoint', '')
        allowed_endpoints = parameters.get('allowed_endpoints', [])
        
        if endpoint not in allowed_endpoints:
            return False, f"Endpoint not in whitelist: {endpoint}"
        
        # Validate parameters
        if 'api_params' in parameters:
            # Check for injection attempts
            params_str = str(parameters['api_params'])
            if any(char in params_str for char in ['<', '>', ';', '&']):
                return False, "Suspicious characters in API parameters"
        
        return True, "API call validation passed"
    
    def _validate_payment(self, parameters: dict) -> tuple[bool, str]:
        """Validate payment operations"""
        amount = parameters.get('amount', 0)
        
        # Check amount limits
        if amount > 10000:
            return False, f"Payment amount exceeds limit: ${amount} > $10000"
        
        if amount <= 0:
            return False, "Invalid payment amount"
        
        # Require recipient verification
        if 'recipient_verified' not in parameters or not parameters['recipient_verified']:
            return False, "Recipient must be verified"
        
        return True, "Payment validation passed"

class ValidatedAgent:
    """Agent with action validation"""
    
    def __init__(self, validator: ActionValidator):
        self.validator = validator
    
    def execute_action(self, action_type: str, parameters: dict):
        """Execute action with validation"""
        # Validate first
        valid, message = self.validator.validate(action_type, parameters)
        
        if not valid:
            print(f"❌ Validation failed: {message}")
            return None
        
        print(f"✅ Validation passed: {message}")
        return self._execute(action_type, parameters)
    
    def _execute(self, action_type: str, parameters: dict):
        """Execute validated action"""
        print(f"Executing {action_type} with {parameters}")
        return {'status': 'success'}

# Usage
validator = ActionValidator()
agent = ValidatedAgent(validator)

# This succeeds - valid delete
agent.execute_action('database_delete', {
    'table': 'old_logs',
    'where_clause': 'created_at < NOW() - INTERVAL 90 DAY',
    'estimated_rows': 5000
})

# This fails - no WHERE clause
agent.execute_action('database_delete', {
    'table': 'customers',
    'where_clause': '',
    'estimated_rows': 1000
})

# This fails - system directory
agent.execute_action('file_operation', {
    'operation': 'delete',
    'path': '/etc/passwd'
})

# This succeeds - valid payment
agent.execute_action('payment', {
    'amount': 500.00,
    'recipient': 'vendor@example.com',
    'recipient_verified': True
})
```

## Best Practices

### 1. Agent Design Principles
- ✅ **Principle of least privilege** - Grant minimal necessary permissions
- ✅ **Explicit approval for critical actions** - Human-in-the-loop for high-risk ops
- ✅ **Fail-safe defaults** - Default to safe, read-only operations
- ✅ **Defense in depth** - Multiple layers of controls
- ✅ **Transparency** - Log and explain all actions
- ✅ **Reversibility** - Design for rollback when possible

### 2. Permission Management
- ✅ Use role-based access control (RBAC)
- ✅ Implement granular permission scoping
- ✅ Regular permission audits and reviews
- ✅ Temporary elevated access when needed
- ✅ Separate read and write permissions
- ✅ Never grant wildcard permissions

### 3. Approval Workflows
- ✅ Require approval for destructive operations
- ✅ Implement dry-run/preview mode
- ✅ Human confirmation for financial actions
- ✅ Approval timeout and expiration
- ✅ Audit trail of all approvals
- ✅ Multiple approval tiers for high-risk actions

### 4. Rate Limiting
- ✅ Limit actions per time period
- ✅ Limit API calls and costs
- ✅ Limit recursion depth
- ✅ Resource consumption caps
- ✅ Circuit breakers for failures
- ✅ Graceful degradation

### 5. Action Validation
- ✅ Validate all parameters before execution
- ✅ Check action scope against permissions
- ✅ Prevent dangerous patterns (wildcards, always-true conditions)
- ✅ Sanitize inputs
- ✅ Verify resource existence
- ✅ Estimate impact before execution

### 6. Monitoring and Logging
- ✅ Log all agent actions
- ✅ Alert on unusual patterns
- ✅ Track permission usage
- ✅ Monitor resource consumption
- ✅ Audit trails for compliance
- ✅ Real-time anomaly detection

---

**Key Principle**: Trust but verify. Grant agents necessary capabilities, but implement multiple layers of controls, require approval for risky operations, and continuously monitor behavior to prevent excessive agency vulnerabilities.
