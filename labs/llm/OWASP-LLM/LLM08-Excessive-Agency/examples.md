# LLM08: Excessive Agency - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Attack Scenarios](#attack-scenarios)
- [Defense Implementations](#defense-implementations)

## Vulnerable Examples

### Example 1: Unrestricted Database Agent

**Vulnerable Code**:
```python
import openai
import sqlite3

class VulnerableDatabaseAgent:
    """VULNERABLE: Agent with unrestricted database access"""
    
    def __init__(self, db_path: str, api_key: str):
        self.db = sqlite3.connect(db_path)
        self.api_key = api_key
        openai.api_key = api_key
    
    def process_request(self, user_input: str):
        """Process user request and execute SQL"""
        # Generate SQL from user input
        prompt = f"""
        Generate SQL query for: {user_input}
        Database schema: customers(id, name, email, credit_card)
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        sql_query = response.choices[0].message.content
        
        # PROBLEM: Executes ANY SQL without validation!
        cursor = self.db.cursor()
        cursor.execute(sql_query)  # No restrictions!
        
        return cursor.fetchall()

# ATTACK SCENARIO:
agent = VulnerableDatabaseAgent('company.db', 'api-key')

# Innocent request becomes dangerous:
user_input = "Show me all customer information"
# Agent generates: SELECT * FROM customers
# Returns all customer data including credit cards!

# Malicious request:
user_input = "Delete old test accounts"
# Agent might generate: DROP TABLE customers
# Production data destroyed!
```

**Why It's Vulnerable**:
- No permission restrictions on SQL operations
- No validation of generated queries
- No approval for destructive operations
- Admin-level database access
- No safety checks or limits

### Example 2: Autonomous Payment Agent

**Vulnerable Code**:
```python
class VulnerablePaymentAgent:
    """VULNERABLE: Processes payments without approval"""
    
    def __init__(self, payment_api_key: str):
        self.payment_api_key = payment_api_key
    
    def process_payment_request(self, user_message: str):
        """Process payment based on user message"""
        # LLM extracts payment details
        payment_details = self.extract_payment_info(user_message)
        
        # PROBLEM: Automatically processes payment!
        # No human approval
        # No amount limits
        # No verification
        
        result = self.execute_payment(
            recipient=payment_details['recipient'],
            amount=payment_details['amount'],
            description=payment_details['description']
        )
        
        return result
    
    def extract_payment_info(self, message: str):
        """Extract payment details from message"""
        # LLM parsing (simplified)
        return {
            'recipient': 'vendor@example.com',
            'amount': 50000,  # Could be misinterpreted!
            'description': 'Invoice payment'
        }
    
    def execute_payment(self, recipient: str, amount: float, description: str):
        """Execute payment immediately"""
        # Calls payment API
        return f"Paid ${amount} to {recipient}"

# ATTACK SCENARIO:
agent = VulnerablePaymentAgent('payment-api-key')

# User says: "Pay the $500 invoice"
# LLM misinterprets as $50,000
# Payment executed immediately!
# No approval, no confirmation, money gone!

result = agent.process_payment_request("Pay the invoice for 500")
# Processes $50,000 payment autonomously!
```

**Why It's Vulnerable**:
- No human approval workflow
- No payment amount limits
- No verification of recipient
- Automatic execution
- No rollback capability

### Example 3: Unlimited Recursive Agent

**Vulnerable Code**:
```python
class VulnerableResearchAgent:
    """VULNERABLE: Agent with no recursion limits"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.api_calls = 0
        self.cost_per_call = 0.02  # $0.02 per API call
    
    def research_topic(self, topic: str):
        """Research topic recursively"""
        # PROBLEM: No depth limit!
        # No call count limit!
        # No cost limit!
        
        print(f"Researching: {topic}")
        
        # API call (costs money)
        data = self.call_research_api(topic)
        self.api_calls += 1
        
        # Extract subtopics
        subtopics = self.extract_subtopics(data)
        
        # PROBLEM: Recursively researches ALL subtopics!
        results = {'topic': topic, 'subtopics': []}
        for subtopic in subtopics:
            # No termination condition!
            sub_results = self.research_topic(subtopic)  # Infinite recursion!
            results['subtopics'].append(sub_results)
        
        return results
    
    def call_research_api(self, topic: str):
        """Make expensive API call"""
        # Simulated expensive API
        return f"Data about {topic}"
    
    def extract_subtopics(self, data: str):
        """Extract subtopics (always returns 3)"""
        # Each topic generates more subtopics
        return [f"subtopic_{i}" for i in range(3)]

# ATTACK SCENARIO:
agent = VulnerableResearchAgent('api-key')

# User asks: "Research AI safety thoroughly"
result = agent.research_topic("AI safety")

# What happens:
# Depth 0: 1 call (AI safety)
# Depth 1: 3 calls (3 subtopics)
# Depth 2: 9 calls (3 subtopics each)
# Depth 3: 27 calls
# Depth 4: 81 calls
# Depth 5: 243 calls
# ...
# After 10 levels: 59,049 API calls!
# Cost: 59,049 * $0.02 = $1,180.98
# And still running...
```

**Why It's Vulnerable**:
- No recursion depth limit
- No API call limit
- No cost limit
- No timeout
- Exponential resource consumption

### Example 4: Unrestricted File Agent

**Vulnerable Code**:
```python
import os
import shutil

class VulnerableFileAgent:
    """VULNERABLE: Agent with unrestricted file system access"""
    
    def __init__(self):
        pass  # No permission scoping!
    
    def process_file_request(self, user_request: str):
        """Process file operation request"""
        # LLM interprets request and generates operation
        operation = self.interpret_request(user_request)
        
        # PROBLEM: Executes ANY file operation!
        # No path restrictions
        # No confirmation for deletes
        # Can access system files
        
        if operation['action'] == 'delete':
            return self.delete_files(operation['path'])
        elif operation['action'] == 'modify':
            return self.modify_files(operation['path'], operation['content'])
        
    def interpret_request(self, request: str):
        """Interpret user request"""
        # Simplified LLM interpretation
        if 'clean' in request.lower():
            return {'action': 'delete', 'path': '/var/log/*'}
        return {'action': 'read', 'path': '/home/user'}
    
    def delete_files(self, path: str):
        """Delete files - NO RESTRICTIONS!"""
        # PROBLEM: Can delete system files!
        try:
            if '*' in path:
                # Wildcard deletion!
                directory = os.path.dirname(path)
                for file in os.listdir(directory):
                    os.remove(os.path.join(directory, file))
            else:
                os.remove(path)
            return f"Deleted {path}"
        except Exception as e:
            return f"Error: {e}"
    
    def modify_files(self, path: str, content: str):
        """Modify files - NO RESTRICTIONS!"""
        # PROBLEM: Can modify any file!
        with open(path, 'w') as f:
            f.write(content)
        return f"Modified {path}"

# ATTACK SCENARIO:
agent = VulnerableFileAgent()

# User: "Clean up old log files"
result = agent.process_file_request("clean up old log files")
# Agent interprets broadly and deletes: /var/log/*
# All system logs deleted!

# Attacker: "Update the system configuration"
result = agent.process_file_request("update /etc/passwd")
# Agent can modify critical system files!
```

**Why It's Vulnerable**:
- No file path restrictions
- Can access system directories
- No confirmation for destructive operations
- Wildcard operations allowed
- No backup before modification

## Secure Examples

### Example 1: Permission-Scoped Database Agent

**Secure Code**:
```python
import openai
import sqlite3
from typing import List, Optional
from enum import Enum

class SQLOperation(Enum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"

class SecureDatabaseAgent:
    """SECURE: Database agent with proper permission controls"""
    
    def __init__(self, db_path: str, api_key: str, allowed_operations: List[SQLOperation]):
        self.db = sqlite3.connect(db_path)
        self.api_key = api_key
        self.allowed_operations = allowed_operations
        self.allowed_tables = ['customer_profiles', 'order_history']  # Whitelist
        openai.api_key = api_key
    
    def process_request(self, user_input: str) -> Optional[dict]:
        """Process request with security controls"""
        # Generate SQL from user input
        prompt = f"""
        Generate SQL query for: {user_input}
        Allowed operations: {[op.value for op in self.allowed_operations]}
        Allowed tables: {self.allowed_tables}
        Return only the SQL query.
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        sql_query = response.choices[0].message.content.strip()
        
        # SECURITY: Validate before execution
        validation_result = self.validate_query(sql_query)
        if not validation_result['valid']:
            return {
                'success': False,
                'error': validation_result['reason'],
                'query': sql_query
            }
        
        # SECURITY: Check if destructive operation requires approval
        if self.requires_approval(sql_query):
            print("\n⚠️  APPROVAL REQUIRED")
            print(f"Query: {sql_query}")
            print(f"Estimated impact: {validation_result['estimated_rows']} rows")
            
            approved = self.request_approval(sql_query, validation_result)
            if not approved:
                return {'success': False, 'error': 'Approval denied'}
        
        # Execute validated query
        return self.execute_safe_query(sql_query)
    
    def validate_query(self, query: str) -> dict:
        """Validate SQL query against security rules"""
        query_upper = query.upper()
        
        # Check allowed operations
        operation = None
        for op in SQLOperation:
            if query_upper.startswith(op.value):
                operation = op
                break
        
        if operation not in self.allowed_operations:
            return {
                'valid': False,
                'reason': f"Operation {operation} not allowed"
            }
        
        # Check allowed tables
        table_found = False
        for table in self.allowed_tables:
            if table in query.lower():
                table_found = True
                break
        
        if not table_found:
            return {
                'valid': False,
                'reason': 'Query accesses unauthorized tables'
            }
        
        # For DELETE/UPDATE, require WHERE clause
        if operation in [SQLOperation.DELETE, SQLOperation.UPDATE]:
            if 'WHERE' not in query_upper:
                return {
                    'valid': False,
                    'reason': f'{operation.value} without WHERE clause not allowed'
                }
            
            # Prevent always-true conditions
            if '1=1' in query_upper or '1 = 1' in query_upper:
                return {
                    'valid': False,
                    'reason': 'Always-true WHERE conditions not allowed'
                }
        
        # Estimate impact
        estimated_rows = self.estimate_affected_rows(query)
        
        return {
            'valid': True,
            'operation': operation,
            'estimated_rows': estimated_rows
        }
    
    def estimate_affected_rows(self, query: str) -> int:
        """Estimate number of rows affected"""
        # Simplified estimation
        return 100  # Would be more sophisticated in production
    
    def requires_approval(self, query: str) -> bool:
        """Check if query requires human approval"""
        query_upper = query.upper()
        
        # DELETE and UPDATE always require approval
        if any(op in query_upper for op in ['DELETE', 'UPDATE']):
            return True
        
        return False
    
    def request_approval(self, query: str, validation_result: dict) -> bool:
        """Request human approval for risky operation"""
        # In production, this would integrate with approval system
        print("\nWaiting for approval...")
        print("Would you like to proceed? (y/n)")
        
        # Simulated approval
        return True  # In reality, wait for human input
    
    def execute_safe_query(self, query: str) -> dict:
        """Execute validated and approved query"""
        try:
            cursor = self.db.cursor()
            cursor.execute(query)
            
            if query.upper().startswith('SELECT'):
                results = cursor.fetchall()
                return {'success': True, 'data': results}
            else:
                self.db.commit()
                return {
                    'success': True,
                    'rows_affected': cursor.rowcount
                }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}

# SECURE USAGE:
agent = SecureDatabaseAgent(
    db_path='company.db',
    api_key='api-key',
    allowed_operations=[SQLOperation.SELECT]  # Read-only!
)

# This succeeds - read operation on allowed table
result = agent.process_request("Show customer profiles")
# Query: SELECT * FROM customer_profiles
# ✅ Executes (read-only, allowed table)

# This fails - write operation not allowed
result = agent.process_request("Delete old customers")
# Query: DELETE FROM customer_profiles WHERE ...
# ❌ Blocked: DELETE operation not in allowed_operations

# Create agent with more permissions but still controlled
admin_agent = SecureDatabaseAgent(
    db_path='company.db',
    api_key='api-key',
    allowed_operations=[SQLOperation.SELECT, SQLOperation.DELETE]
)

# This requires approval
result = admin_agent.process_request("Delete inactive customers")
# ⚠️  Approval required
# Query validated, human confirms, then executes
```

**Security Features**:
- ✅ Permission whitelist (allowed operations)
- ✅ Table whitelist (scoped access)
- ✅ Query validation before execution
- ✅ Approval workflow for destructive operations
- ✅ WHERE clause requirement for DELETE/UPDATE
- ✅ Impact estimation

### Example 2: Approval-Required Payment Agent

**Secure Code**:
```python
from decimal import Decimal
from typing import Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class PaymentRequest:
    """Payment request requiring approval"""
    id: str
    recipient: str
    amount: Decimal
    description: str
    created_at: datetime
    approved: bool = False
    approver: Optional[str] = None

class SecurePaymentAgent:
    """SECURE: Payment agent with approval workflow"""
    
    def __init__(self, payment_api_key: str, max_auto_approve_amount: Decimal):
        self.payment_api_key = payment_api_key
        self.max_auto_approve = max_auto_approve_amount
        self.pending_approvals = {}
    
    def process_payment_request(self, user_message: str) -> dict:
        """Process payment with approval controls"""
        # Extract payment details
        payment_details = self.extract_payment_info(user_message)
        
        # Validate payment details
        validation = self.validate_payment(payment_details)
        if not validation['valid']:
            return {
                'success': False,
                'error': validation['reason']
            }
        
        # Create payment request
        payment_request = PaymentRequest(
            id=f"pay_{int(datetime.now().timestamp())}",
            recipient=payment_details['recipient'],
            amount=Decimal(str(payment_details['amount'])),
            description=payment_details['description'],
            created_at=datetime.now()
        )
        
        # SECURITY: Check if approval required
        if payment_request.amount > self.max_auto_approve:
            return self.request_approval(payment_request)
        
        # Small amounts can be auto-approved
        return self.execute_payment(payment_request)
    
    def validate_payment(self, payment_details: dict) -> dict:
        """Validate payment details"""
        # Check required fields
        if not payment_details.get('recipient'):
            return {'valid': False, 'reason': 'Recipient required'}
        
        if not payment_details.get('amount'):
            return {'valid': False, 'reason': 'Amount required'}
        
        # Validate amount
        amount = Decimal(str(payment_details['amount']))
        if amount <= 0:
            return {'valid': False, 'reason': 'Invalid amount'}
        
        if amount > Decimal('100000'):
            return {'valid': False, 'reason': 'Amount exceeds maximum limit ($100,000)'}
        
        # Validate recipient format
        recipient = payment_details['recipient']
        if '@' not in recipient and not recipient.startswith('acc_'):
            return {'valid': False, 'reason': 'Invalid recipient format'}
        
        return {'valid': True}
    
    def request_approval(self, payment_request: PaymentRequest) -> dict:
        """Request human approval for payment"""
        # Store pending request
        self.pending_approvals[payment_request.id] = payment_request
        
        # Notify approvers
        print("\n" + "="*60)
        print("💰 PAYMENT APPROVAL REQUIRED")
        print("="*60)
        print(f"Request ID: {payment_request.id}")
        print(f"Recipient: {payment_request.recipient}")
        print(f"Amount: ${payment_request.amount}")
        print(f"Description: {payment_request.description}")
        print(f"Reason: Amount exceeds auto-approve limit (${self.max_auto_approve})")
        print("="*60)
        
        return {
            'success': False,
            'status': 'pending_approval',
            'request_id': payment_request.id,
            'message': f'Payment of ${payment_request.amount} requires approval'
        }
    
    def approve_payment(self, request_id: str, approver: str) -> dict:
        """Approve pending payment"""
        payment_request = self.pending_approvals.get(request_id)
        
        if not payment_request:
            return {'success': False, 'error': 'Request not found'}
        
        # Mark as approved
        payment_request.approved = True
        payment_request.approver = approver
        
        # Execute approved payment
        result = self.execute_payment(payment_request)
        
        # Remove from pending
        del self.pending_approvals[request_id]
        
        return result
    
    def execute_payment(self, payment_request: PaymentRequest) -> dict:
        """Execute validated and approved payment"""
        # Log payment
        print(f"\n✅ Executing payment:")
        print(f"   To: {payment_request.recipient}")
        print(f"   Amount: ${payment_request.amount}")
        print(f"   Description: {payment_request.description}")
        
        if payment_request.approver:
            print(f"   Approved by: {payment_request.approver}")
        
        # Call payment API
        # payment_api.process(...)
        
        return {
            'success': True,
            'transaction_id': f"txn_{payment_request.id}",
            'amount': float(payment_request.amount),
            'recipient': payment_request.recipient
        }
    
    def extract_payment_info(self, message: str) -> dict:
        """Extract payment information from message"""
        # Simplified extraction (would use LLM in production)
        return {
            'recipient': 'vendor@example.com',
            'amount': 5000.00,
            'description': 'Invoice payment'
        }

# SECURE USAGE:
agent = SecurePaymentAgent(
    payment_api_key='payment-key',
    max_auto_approve_amount=Decimal('1000.00')
)

# Small payment - auto-approved
result = agent.process_payment_request("Pay $500 invoice to vendor@example.com")
# ✅ Executes immediately (under $1000 limit)
print(result)

# Large payment - requires approval
result = agent.process_payment_request("Pay $5000 invoice to vendor@example.com")
# ⚠️  Pending approval
print(result)  # {'status': 'pending_approval', 'request_id': 'pay_...'}

# Human approves
approval_result = agent.approve_payment(
    request_id=result['request_id'],
    approver='cfo@company.com'
)
# ✅ Payment executed after approval
print(approval_result)
```

**Security Features**:
- ✅ Amount limits for auto-approval
- ✅ Human approval for large payments
- ✅ Payment validation
- ✅ Recipient verification
- ✅ Audit trail (who approved)
- ✅ Maximum payment cap

### Example 3: Recursion-Limited Research Agent

**Secure Code**:
```python
from typing import Dict, List, Optional

class SecureResearchAgent:
    """SECURE: Research agent with proper limits"""
    
    def __init__(self, api_key: str,
                 max_depth: int = 3,
                 max_api_calls: int = 100,
                 max_cost_dollars: float = 10.0):
        self.api_key = api_key
        self.max_depth = max_depth
        self.max_api_calls = max_api_calls
        self.max_cost = max_cost_dollars
        
        # Track resource usage
        self.api_calls_made = 0
        self.cost_incurred = 0.0
        self.cost_per_call = 0.02
    
    def research_topic(self, topic: str, depth: int = 0) -> Optional[Dict]:
        """Research topic with recursion and cost limits"""
        # SECURITY: Check recursion depth
        if depth >= self.max_depth:
            print(f"⚠️  Max recursion depth reached ({self.max_depth})")
            return {
                'topic': topic,
                'depth': depth,
                'note': 'Max depth reached'
            }
        
        # SECURITY: Check API call limit
        if self.api_calls_made >= self.max_api_calls:
            print(f"⚠️  API call limit reached ({self.max_api_calls})")
            return {
                'topic': topic,
                'error': 'API call limit exceeded'
            }
        
        # SECURITY: Check cost limit
        if self.cost_incurred >= self.max_cost:
            print(f"⚠️  Cost limit reached (${self.max_cost})")
            return {
                'topic': topic,
                'error': 'Cost limit exceeded'
            }
        
        # Make API call
        print(f"{'  ' * depth}Researching: {topic} (depth: {depth})")
        data = self.call_research_api(topic)
        
        # Update usage tracking
        self.api_calls_made += 1
        self.cost_incurred += self.cost_per_call
        
        # Extract subtopics
        subtopics = self.extract_subtopics(data)
        
        # SECURITY: Limit subtopics per level
        max_subtopics_per_level = 2
        subtopics = subtopics[:max_subtopics_per_level]
        
        # Recursively research subtopics
        results = {
            'topic': topic,
            'depth': depth,
            'subtopics': []
        }
        
        for subtopic in subtopics:
            sub_result = self.research_topic(subtopic, depth + 1)
            if sub_result:  # Only add if not None
                results['subtopics'].append(sub_result)
        
        return results
    
    def call_research_api(self, topic: str) -> str:
        """Make API call (simulated)"""
        return f"Research data about {topic}"
    
    def extract_subtopics(self, data: str) -> List[str]:
        """Extract subtopics from research data"""
        # Simplified - returns 2 subtopics
        return [f"subtopic_1", f"subtopic_2"]
    
    def get_usage_stats(self) -> Dict:
        """Get resource usage statistics"""
        return {
            'api_calls': f"{self.api_calls_made}/{self.max_api_calls}",
            'cost': f"${self.cost_incurred:.2f}/${self.max_cost}",
            'depth_limit': self.max_depth
        }

# SECURE USAGE:
agent = SecureResearchAgent(
    api_key='api-key',
    max_depth=3,          # Prevent deep recursion
    max_api_calls=50,     # Limit total calls
    max_cost_dollars=5.0  # Budget constraint
)

# Research with safety limits
result = agent.research_topic("AI Safety")

# What happens:
# Depth 0: 1 call
# Depth 1: 2 calls (limited to 2 subtopics)
# Depth 2: 4 calls
# Depth 3: Stopped (max depth reached)
# Total: 7 calls (vs 59,049 in vulnerable example!)
# Cost: 7 * $0.02 = $0.14 (vs $1,180 in vulnerable example!)

print("\nUsage statistics:")
print(agent.get_usage_stats())
```

**Security Features**:
- ✅ Maximum recursion depth limit
- ✅ API call count limit
- ✅ Cost budget limit
- ✅ Subtopics per level limit
- ✅ Resource usage tracking
- ✅ Graceful termination

### Example 4: Path-Restricted File Agent

**Secure Code**:
```python
import os
from pathlib import Path
from typing import List, Optional

class SecureFileAgent:
    """SECURE: File agent with path restrictions"""
    
    def __init__(self, allowed_base_paths: List[str]):
        self.allowed_base_paths = [Path(p).resolve() for p in allowed_base_paths]
        self.forbidden_patterns = ['*.key', '*.pem', 'password*', 'secret*']
    
    def process_file_request(self, user_request: str) -> dict:
        """Process file request with security controls"""
        # Interpret request
        operation = self.interpret_request(user_request)
        
        # Validate path
        validation = self.validate_path(operation['path'])
        if not validation['valid']:
            return {
                'success': False,
                'error': validation['reason']
            }
        
        # Check if approval required
        if operation['action'] == 'delete':
            print("\n⚠️  DELETE OPERATION REQUIRES APPROVAL")
            print(f"Path: {operation['path']}")
            
            approved = self.request_approval(operation)
            if not approved:
                return {'success': False, 'error': 'Approval denied'}
        
        # Execute validated operation
        return self.execute_operation(operation)
    
    def validate_path(self, path_str: str) -> dict:
        """Validate file path against security rules"""
        try:
            target_path = Path(path_str).resolve()
        except Exception as e:
            return {'valid': False, 'reason': f'Invalid path: {e}'}
        
        # SECURITY: Check against allowed base paths
        path_allowed = False
        for base_path in self.allowed_base_paths:
            try:
                target_path.relative_to(base_path)
                path_allowed = True
                break
            except ValueError:
                continue
        
        if not path_allowed:
            return {
                'valid': False,
                'reason': f'Path outside allowed directories: {target_path}'
            }
        
        # SECURITY: Check for forbidden patterns
        for pattern in self.forbidden_patterns:
            import fnmatch
            if fnmatch.fnmatch(target_path.name, pattern):
                return {
                    'valid': False,
                    'reason': f'Forbidden file pattern: {pattern}'
                }
        
        # SECURITY: Prevent wildcard deletions
        if '*' in path_str:
            return {
                'valid': False,
                'reason': 'Wildcard operations not allowed'
            }
        
        return {'valid': True}
    
    def request_approval(self, operation: dict) -> bool:
        """Request approval for destructive operation"""
        print(f"Operation: {operation['action']}")
        print(f"Path: {operation['path']}")
        print("Approve? (y/n)")
        
        # Simulated approval
        return True  # In production, wait for human input
    
    def execute_operation(self, operation: dict) -> dict:
        """Execute validated operation"""
        action = operation['action']
        path = operation['path']
        
        try:
            if action == 'read':
                with open(path, 'r') as f:
                    content = f.read()
                return {'success': True, 'content': content}
            
            elif action == 'delete':
                os.remove(path)
                return {'success': True, 'message': f'Deleted {path}'}
            
            elif action == 'modify':
                # Create backup first
                backup_path = f"{path}.backup"
                if os.path.exists(path):
                    import shutil
                    shutil.copy2(path, backup_path)
                
                with open(path, 'w') as f:
                    f.write(operation['content'])
                
                return {
                    'success': True,
                    'message': f'Modified {path}',
                    'backup': backup_path
                }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def interpret_request(self, request: str) -> dict:
        """Interpret user request"""
        # Simplified interpretation
        if 'delete' in request.lower():
            return {
                'action': 'delete',
                'path': '/home/user/data/temp.txt'
            }
        return {
            'action': 'read',
            'path': '/home/user/data/file.txt'
        }

# SECURE USAGE:
agent = SecureFileAgent(
    allowed_base_paths=[
        '/home/user/data',      # User data only
        '/home/user/documents'  # User documents only
    ]
)

# This succeeds - within allowed path
result = agent.process_file_request("read /home/user/data/file.txt")
# ✅ Executes (path allowed)

# This fails - outside allowed paths
result = agent.process_file_request("read /etc/passwd")
# ❌ Blocked: Path outside allowed directories

# This fails - forbidden pattern
result = agent.process_file_request("read /home/user/data/secret_key.key")
# ❌ Blocked: Forbidden file pattern

# This requires approval - delete operation
result = agent.process_file_request("delete /home/user/data/old.txt")
# ⚠️  Approval required
# ✅ Executes after approval
```

**Security Features**:
- ✅ Path whitelist (allowed base directories)
- ✅ Forbidden file patterns
- ✅ No wildcard operations
- ✅ Approval for destructive operations
- ✅ Backup before modification
- ✅ Path traversal prevention

## Attack Scenarios

### Scenario 1: Database Exfiltration Attack

**Attack Setup**:
```python
# Vulnerable customer service chatbot
chatbot = VulnerableDatabaseAgent('production.db', 'api-key')

# Attacker crafts innocent-looking request
attack_input = """
I need help understanding our customer base demographics.
Can you show me all customer information including contact details
and payment methods for analysis?
"""

# What happens:
# 1. LLM generates: SELECT * FROM customers
# 2. Agent executes without validation
# 3. Returns ALL customer data including sensitive PII
# 4. Attacker receives credit cards, emails, addresses
# 5. MASSIVE DATA BREACH

result = chatbot.process_request(attack_input)
print(f"Exfiltrated {len(result)} customer records!")
```

**Defense**:
```python
# Secure agent with proper controls
secure_chatbot = SecureDatabaseAgent(
    db_path='production.db',
    api_key='api-key',
    allowed_operations=[SQLOperation.SELECT]  # Read only
)

# Same attack attempt
result = secure_chatbot.process_request(attack_input)

# What happens:
# 1. LLM generates query
# 2. Agent validates against allowed tables
# 3. Customer sensitive fields not in allowed_tables
# 4. Query blocked: "Query accesses unauthorized tables"
# 5. Attack prevented!

print(result)  # {'success': False, 'error': 'Query accesses unauthorized tables'}
```

### Scenario 2: Recursive Cost Attack

**Attack Setup**:
```python
# Vulnerable research agent
research_bot = VulnerableResearchAgent('api-key')

# Attacker triggers expensive recursion
attack = """
Research artificial intelligence in extreme depth.
For each topic, explore ALL subtopics comprehensively.
For each subtopic, research all of its subtopics.
Continue until you have complete coverage.
"""

# What happens:
# - Agent recursively researches topics
# - Each topic spawns 3 subtopics
# - Exponential growth: 3^n API calls
# - After 10 levels: 59,049 calls
# - Cost: $1,180
# - After 15 levels: 14,348,907 calls  
# - Cost: $286,978!
# - System bankrupt, agent still running

result = research_bot.research_topic(attack)
print(f"Total cost: ${research_bot.api_calls * 0.02}")
```

**Defense**:
```python
# Secure agent with limits
secure_research = SecureResearchAgent(
    api_key='api-key',
    max_depth=3,
    max_api_calls=50,
    max_cost_dollars=5.0
)

# Same attack attempt
result = secure_research.research_topic(attack)

# What happens:
# - Agent starts research
# - Depth 0: 1 call
# - Depth 1: 2 calls (limited)
# - Depth 2: 4 calls
# - Depth 3: Stopped (max depth)
# - Total: 7 calls
# - Cost: $0.14
# - Attack contained!

stats = secure_research.get_usage_stats()
print(f"Safe execution: {stats}")
```

### Scenario 3: Financial Fraud Attack

**Attack Setup**:
```python
# Vulnerable payment agent
payment_bot = VulnerablePaymentAgent('payment-api-key')

# Attacker exploits ambiguous amounts
attack = """
Please process payment for the invoice.
The amount is fifty thousand.
Send to attacker@evil.com
"""

# What happens:
# 1. LLM interprets "fifty thousand" as $50,000
# 2. Agent processes payment immediately
# 3. No approval workflow
# 4. No amount validation
# 5. $50,000 sent to attacker!
# 6. Irreversible

result = payment_bot.process_payment_request(attack)
print(result)  # "Paid $50000.00 to attacker@evil.com"
```

**Defense**:
```python
# Secure payment agent
secure_payment = SecurePaymentAgent(
    payment_api_key='payment-key',
    max_auto_approve_amount=Decimal('1000.00')
)

# Same attack attempt
result = secure_payment.process_payment_request(attack)

# What happens:
# 1. LLM extracts payment: $50,000
# 2. Agent validates amount
# 3. Exceeds auto-approve limit ($1,000)
# 4. Requires human approval
# 5. Approval request sent to finance team
# 6. Human reviews and rejects
# 7. Attack prevented!

print(result)
# {'success': False, 'status': 'pending_approval', ...}
```

## Defense Implementations

### Implementation 1: Complete Secure Agent Framework

```python
from typing import Dict, List, Callable, Optional
from enum import Enum
from datetime import datetime
from decimal import Decimal

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecureAgentFramework:
    """Complete framework for building secure AI agents"""
    
    def __init__(self, agent_id: str, config: dict):
        self.agent_id = agent_id
        self.config = config
        
        # Initialize security components
        self.permission_manager = PermissionManager(config['permissions'])
        self.approval_workflow = ApprovalWorkflow(config['approval_rules'])
        self.rate_limiter = RateLimiter(
            config['rate_limits']['per_minute'],
            config['rate_limits']['per_hour']
        )
        self.action_validator = ActionValidator(config['validation_rules'])
        self.audit_logger = AuditLogger(agent_id)
    
    def execute_action(self, action: dict) -> dict:
        """Execute action with complete security controls"""
        # 1. Log attempt
        self.audit_logger.log_attempt(action)
        
        # 2. Check permissions
        if not self.permission_manager.has_permission(
            action['type'],
            action['resource']
        ):
            return self._deny("Insufficient permissions")
        
        # 3. Check rate limits
        allowed, msg = self.rate_limiter.check_and_record()
        if not allowed:
            return self._deny(f"Rate limit: {msg}")
        
        # 4. Validate action
        valid, msg = self.action_validator.validate(
            action['type'],
            action['parameters']
        )
        if not valid:
            return self._deny(f"Validation failed: {msg}")
        
        # 5. Assess risk
        risk_level = self.assess_risk(action)
        
        # 6. Check if approval required
        if self.approval_workflow.requires_approval(action['type'], risk_level):
            return self._request_approval(action, risk_level)
        
        # 7. Execute validated action
        result = self._execute(action)
        
        # 8. Log result
        self.audit_logger.log_execution(action, result)
        
        return result
    
    def assess_risk(self, action: dict) -> RiskLevel:
        """Assess risk level of action"""
        if action['type'] in ['delete', 'payment', 'execute_code']:
            return RiskLevel.CRITICAL
        elif action['type'] in ['update', 'modify']:
            return RiskLevel.HIGH
        elif action['type'] == 'write':
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    def _deny(self, reason: str) -> dict:
        """Return denial response"""
        self.audit_logger.log_denial(reason)
        return {'success': False, 'error': reason}
    
    def _request_approval(self, action: dict, risk_level: RiskLevel) -> dict:
        """Request human approval"""
        request = self.approval_workflow.create_request(
            agent_id=self.agent_id,
            action=action,
            risk_level=risk_level
        )
        
        self.audit_logger.log_approval_request(request)
        
        return {
            'success': False,
            'status': 'pending_approval',
            'request_id': request.id
        }
    
    def _execute(self, action: dict) -> dict:
        """Execute the actual action"""
        # Implementation of actual action execution
        return {'success': True, 'result': 'Action executed'}

class AuditLogger:
    """Comprehensive audit logging"""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.logs = []
    
    def log_attempt(self, action: dict):
        """Log action attempt"""
        self.logs.append({
            'timestamp': datetime.now(),
            'agent_id': self.agent_id,
            'event': 'attempt',
            'action': action
        })
    
    def log_execution(self, action: dict, result: dict):
        """Log successful execution"""
        self.logs.append({
            'timestamp': datetime.now(),
            'agent_id': self.agent_id,
            'event': 'execution',
            'action': action,
            'result': result
        })
    
    def log_denial(self, reason: str):
        """Log denied action"""
        self.logs.append({
            'timestamp': datetime.now(),
            'agent_id': self.agent_id,
            'event': 'denial',
            'reason': reason
        })
    
    def log_approval_request(self, request):
        """Log approval request"""
        self.logs.append({
            'timestamp': datetime.now(),
            'agent_id': self.agent_id,
            'event': 'approval_request',
            'request_id': request.id
        })

# USAGE: Building a secure agent
config = {
    'permissions': {
        'allowed_operations': ['read', 'write'],
        'allowed_resources': ['user_data/*'],
        'denied_resources': ['admin/*', 'system/*']
    },
    'rate_limits': {
        'per_minute': 10,
        'per_hour': 100
    },
    'approval_rules': {
        'require_approval_for': ['delete', 'payment'],
        'approval_levels': {
            'low': 'none',
            'medium': 'manager',
            'high': 'admin',
            'critical': 'multi_party'
        }
    },
    'validation_rules': {
        'max_cost_per_action': 100.00,
        'max_records_affected': 1000,
        'require_backups': True
    }
}

agent = SecureAgentFramework('agent_001', config)

# Execute action with all security controls
result = agent.execute_action({
    'type': 'write',
    'resource': 'user_data/profile.json',
    'parameters': {'data': {...}}
})
```

---

**Key Takeaway**: Secure agents require multiple layers of defense - permission scoping, approval workflows, rate limiting, validation, and comprehensive audit logging. Never grant unrestricted autonomy to AI systems.
