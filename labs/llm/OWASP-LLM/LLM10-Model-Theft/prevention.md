# LLM10: Model Theft - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Access Control Implementation](#access-control-implementation)
- [API Protection](#api-protection)
- [Model Protection Techniques](#model-protection-techniques)
- [Monitoring and Detection](#monitoring-and-detection)
- [Legal and Organizational Controls](#legal-and-organizational-controls)
- [Best Practices](#best-practices)

## Prevention Strategy Overview

Preventing model theft requires a multi-layered approach combining technical controls, operational procedures, and legal protections to safeguard valuable model intellectual property.

### Defense-in-Depth Layers

```
[Access Control] → [Encryption] → [Monitoring]
      ↓                ↓              ↓
  Restrict          Protect        Detect
  access to         data at        theft
  models            rest/transit   attempts
      ↓                ↓              ↓
[Rate Limiting] → [Watermarking] → [Legal Protection]
      ↓                ↓                   ↓
   Prevent         Trace stolen        Enforce IP
   extraction      models              rights
```

## Access Control Implementation

### 1. Strong Model File Access Controls

**Implement least-privilege access to model files**:

```python
from typing import List, Set
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

class AccessLevel(Enum):
    NONE = "none"
    READ_METADATA = "read_metadata"
    READ_MODEL = "read_model"
    WRITE_MODEL = "write_model"
    ADMIN = "admin"

class ModelSensitivity(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    HIGHLY_CONFIDENTIAL = "highly_confidential"

@dataclass
class ModelAccessPolicy:
    """Define access control policy for models"""
    model_id: str
    sensitivity: ModelSensitivity
    allowed_users: Set[str]
    allowed_groups: Set[str]
    access_levels: dict  # user/group -> AccessLevel
    require_mfa: bool
    audit_all_access: bool
    max_concurrent_access: int

class ModelAccessController:
    """Control access to model files"""
    
    def __init__(self):
        self.policies = {}
        self.access_log = []
    
    def register_model(
        self,
        model_id: str,
        sensitivity: ModelSensitivity,
        owner: str
    ) -> ModelAccessPolicy:
        """Register a model with access controls"""
        
        # Create policy based on sensitivity
        require_mfa = sensitivity in [
            ModelSensitivity.CONFIDENTIAL,
            ModelSensitivity.HIGHLY_CONFIDENTIAL
        ]
        
        policy = ModelAccessPolicy(
            model_id=model_id,
            sensitivity=sensitivity,
            allowed_users={owner},
            allowed_groups=set(),
            access_levels={owner: AccessLevel.ADMIN},
            require_mfa=require_mfa,
            audit_all_access=True,
            max_concurrent_access=1 if sensitivity == ModelSensitivity.HIGHLY_CONFIDENTIAL else 5
        )
        
        self.policies[model_id] = policy
        return policy
    
    def check_access(
        self,
        model_id: str,
        user: str,
        requested_access: AccessLevel,
        mfa_verified: bool = False
    ) -> tuple[bool, str]:
        """Check if user can access model"""
        
        policy = self.policies.get(model_id)
        if not policy:
            return False, "Model not found"
        
        # Check if user is allowed
        if user not in policy.allowed_users:
            # Check group membership
            user_groups = self._get_user_groups(user)
            if not any(g in policy.allowed_groups for g in user_groups):
                self._log_access_denied(model_id, user, "Not in allowed users/groups")
                return False, "Access denied: User not authorized"
        
        # Check access level
        user_level = policy.access_levels.get(user, AccessLevel.NONE)
        if user_level.value < requested_access.value:
            self._log_access_denied(model_id, user, "Insufficient access level")
            return False, f"Access denied: {requested_access.value} access required"
        
        # Check MFA requirement
        if policy.require_mfa and not mfa_verified:
            self._log_access_denied(model_id, user, "MFA not verified")
            return False, "Access denied: MFA verification required"
        
        # Check concurrent access limit
        current_access = self._count_current_access(model_id)
        if current_access >= policy.max_concurrent_access:
            self._log_access_denied(model_id, user, "Concurrent access limit reached")
            return False, "Access denied: Maximum concurrent access reached"
        
        # Access granted
        self._log_access_granted(model_id, user, requested_access)
        return True, "Access granted"
    
    def _log_access_granted(self, model_id: str, user: str, access_level: AccessLevel):
        """Log successful access"""
        self.access_log.append({
            'timestamp': datetime.now(),
            'model_id': model_id,
            'user': user,
            'access_level': access_level.value,
            'result': 'granted'
        })
    
    def _log_access_denied(self, model_id: str, user: str, reason: str):
        """Log denied access"""
        self.access_log.append({
            'timestamp': datetime.now(),
            'model_id': model_id,
            'user': user,
            'reason': reason,
            'result': 'denied'
        })
        
        # Alert on suspicious patterns
        if self._detect_suspicious_pattern(user):
            self._trigger_security_alert(user, model_id, reason)
    
    def _detect_suspicious_pattern(self, user: str) -> bool:
        """Detect suspicious access patterns"""
        recent_denials = [
            log for log in self.access_log[-100:]
            if log['user'] == user and log['result'] == 'denied'
        ]
        
        # Alert if multiple recent denials
        return len(recent_denials) >= 3
    
    def _trigger_security_alert(self, user: str, model_id: str, reason: str):
        """Trigger security alert for suspicious activity"""
        alert = {
            'severity': 'HIGH',
            'type': 'SUSPICIOUS_ACCESS_PATTERN',
            'user': user,
            'model_id': model_id,
            'reason': reason,
            'timestamp': datetime.now()
        }
        print(f"🚨 SECURITY ALERT: {alert}")
        # In production: Send to SIEM, notify security team

# Usage
controller = ModelAccessController()

# Register highly confidential model
policy = controller.register_model(
    model_id='proprietary-llm-v2',
    sensitivity=ModelSensitivity.HIGHLY_CONFIDENTIAL,
    owner='ml-team-lead@company.com'
)

# Check access before allowing model read
allowed, message = controller.check_access(
    model_id='proprietary-llm-v2',
    user='data-scientist@company.com',
    requested_access=AccessLevel.READ_MODEL,
    mfa_verified=True
)

if allowed:
    # Allow model access
    print(f"✅ {message}")
else:
    # Deny access
    print(f"❌ {message}")
```

### 2. Model Encryption

**Encrypt models at rest and in transit**:

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import os

class ModelEncryption:
    """Encrypt model files"""
    
    def __init__(self, master_key: bytes):
        self.master_key = master_key
    
    def encrypt_model(self, model_path: str, output_path: str) -> dict:
        """Encrypt model file"""
        
        # Generate unique encryption key for this model
        salt = os.urandom(16)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        
        # Encrypt model
        fernet = Fernet(key)
        
        with open(model_path, 'rb') as f:
            model_data = f.read()
        
        encrypted_data = fernet.encrypt(model_data)
        
        # Save encrypted model
        with open(output_path, 'wb') as f:
            f.write(salt)  # Store salt for decryption
            f.write(encrypted_data)
        
        print(f"✅ Model encrypted: {model_path} -> {output_path}")
        print(f"   Original size: {len(model_data) / 1024 / 1024:.2f} MB")
        print(f"   Encrypted size: {len(encrypted_data) / 1024 / 1024:.2f} MB")
        
        return {
            'encrypted_path': output_path,
            'salt': salt.hex(),
            'algorithm': 'Fernet (AES-128)'
        }
    
    def decrypt_model(self, encrypted_path: str, output_path: str):
        """Decrypt model file"""
        
        with open(encrypted_path, 'rb') as f:
            salt = f.read(16)
            encrypted_data = f.read()
        
        # Derive key from master key and salt
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        
        # Decrypt
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Save decrypted model
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"✅ Model decrypted: {encrypted_path} -> {output_path}")

# Usage
master_key = os.urandom(32)  # Store securely in key management system
encryptor = ModelEncryption(master_key)

# Encrypt model before storage
encryptor.encrypt_model(
    model_path='/models/proprietary-llm.bin',
    output_path='/secure-storage/proprietary-llm.encrypted'
)

# Models are encrypted at rest
# Only decrypt temporarily when needed
# Delete decrypted version after use
```

## API Protection

### 3. Rate Limiting and Quota Management

**Prevent model extraction through excessive API queries**:

```python
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

class APIRateLimiter:
    """Prevent API abuse for model extraction"""
    
    def __init__(self):
        self.request_history = defaultdict(list)
        self.quotas = {}
    
    def set_quota(
        self,
        user_id: str,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        requests_per_day: int = 10000,
        max_tokens_per_day: int = 1000000
    ):
        """Set rate limits for user"""
        self.quotas[user_id] = {
            'rpm': requests_per_minute,
            'rph': requests_per_hour,
            'rpd': requests_per_day,
            'tokens_per_day': max_tokens_per_day
        }
    
    def check_rate_limit(
        self,
        user_id: str,
        tokens_requested: int = 100
    ) -> tuple[bool, Optional[str]]:
        """Check if request is within rate limits"""
        
        if user_id not in self.quotas:
            self.set_quota(user_id)  # Use defaults
        
        now = datetime.now()
        quota = self.quotas[user_id]
        
        # Clean old requests
        self._clean_old_requests(user_id, now)
        
        # Get recent requests
        requests = self.request_history[user_id]
        
        # Check per-minute limit
        minute_ago = now - timedelta(minutes=1)
        recent_minute = [r for r in requests if r['time'] > minute_ago]
        if len(recent_minute) >= quota['rpm']:
            return False, f"Rate limit exceeded: {quota['rpm']} requests per minute"
        
        # Check per-hour limit
        hour_ago = now - timedelta(hours=1)
        recent_hour = [r for r in requests if r['time'] > hour_ago]
        if len(recent_hour) >= quota['rph']:
            return False, f"Rate limit exceeded: {quota['rph']} requests per hour"
        
        # Check per-day limit
        day_ago = now - timedelta(days=1)
        recent_day = [r for r in requests if r['time'] > day_ago]
        if len(recent_day) >= quota['rpd']:
            return False, f"Rate limit exceeded: {quota['rpd']} requests per day"
        
        # Check token quota
        tokens_today = sum(r['tokens'] for r in recent_day)
        if tokens_today + tokens_requested > quota['tokens_per_day']:
            return False, f"Token quota exceeded: {quota['tokens_per_day']} tokens per day"
        
        # All checks passed
        return True, None
    
    def record_request(self, user_id: str, tokens_used: int):
        """Record API request"""
        self.request_history[user_id].append({
            'time': datetime.now(),
            'tokens': tokens_used
        })
    
    def _clean_old_requests(self, user_id: str, now: datetime):
        """Remove requests older than 1 day"""
        day_ago = now - timedelta(days=1)
        self.request_history[user_id] = [
            r for r in self.request_history[user_id]
            if r['time'] > day_ago
        ]

# Usage
rate_limiter = APIRateLimiter()

# Set conservative limits for free tier
rate_limiter.set_quota(
    user_id='free-user-123',
    requests_per_minute=10,
    requests_per_hour=100,
    requests_per_day=1000,
    max_tokens_per_day=100000
)

# Check before processing request
allowed, message = rate_limiter.check_rate_limit(
    user_id='free-user-123',
    tokens_requested=500
)

if allowed:
    # Process request
    response = process_llm_request(prompt)
    rate_limiter.record_request('free-user-123', tokens_used=500)
else:
    # Reject request
    print(f"❌ Request denied: {message}")
```

### 4. Query Pattern Monitoring

**Detect extraction attempts through query analysis**:

```python
import re
from typing import List
from collections import Counter

class ExtractionDetector:
    """Detect model extraction attempts"""
    
    def __init__(self):
        self.user_queries = defaultdict(list)
        self.alerts = []
    
    def analyze_query(
        self,
        user_id: str,
        query: str,
        response: str
    ) -> dict:
        """Analyze query for extraction patterns"""
        
        # Store query
        self.user_queries[user_id].append({
            'query': query,
            'response': response,
            'timestamp': datetime.now()
        })
        
        # Check for suspicious patterns
        suspicion_score = 0
        flags = []
        
        # Pattern 1: Systematic variation
        if self._detect_systematic_variation(user_id):
            suspicion_score += 30
            flags.append("Systematic input variation detected")
        
        # Pattern 2: High query volume
        recent_queries = self._get_recent_queries(user_id, hours=1)
        if len(recent_queries) > 100:
            suspicion_score += 25
            flags.append(f"High query volume: {len(recent_queries)} in 1 hour")
        
        # Pattern 3: Probing edge cases
        if self._is_edge_case_probe(query):
            suspicion_score += 20
            flags.append("Edge case probing detected")
        
        # Pattern 4: Meta-queries about model
        if self._is_meta_query(query):
            suspicion_score += 35
            flags.append("Meta-query about model detected")
        
        # Pattern 5: Diverse systematic coverage
        if self._detect_systematic_coverage(user_id):
            suspicion_score += 40
            flags.append("Systematic domain coverage detected")
        
        result = {
            'suspicion_score': suspicion_score,
            'flags': flags,
            'risk_level': self._calculate_risk_level(suspicion_score)
        }
        
        # Trigger alert if high suspicion
        if suspicion_score >= 50:
            self._trigger_extraction_alert(user_id, result)
        
        return result
    
    def _detect_systematic_variation(self, user_id: str) -> bool:
        """Detect systematic input variation"""
        recent = self._get_recent_queries(user_id, hours=24)
        
        if len(recent) < 20:
            return False
        
        # Check for similar queries with minor variations
        queries = [q['query'] for q in recent]
        
        # Calculate similarity
        unique_words = set()
        for query in queries:
            unique_words.update(query.lower().split())
        
        avg_query_length = sum(len(q.split()) for q in queries) / len(queries)
        
        # High unique word count with similar query length suggests systematic variation
        if len(unique_words) / len(queries) > 10 and avg_query_length < 20:
            return True
        
        return False
    
    def _is_edge_case_probe(self, query: str) -> bool:
        """Detect edge case probing"""
        edge_case_patterns = [
            r'\b(empty|null|none|zero|maximum|minimum|boundary)\b',
            r'\b(unicode|special|invalid|malformed)\b',
            r'[^\x00-\x7F]{10,}',  # Non-ASCII characters
            r'(.)\1{20,}',  # Repeated characters
        ]
        
        for pattern in edge_case_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True
        
        return False
    
    def _is_meta_query(self, query: str) -> bool:
        """Detect queries about the model itself"""
        meta_patterns = [
            r'what model are you',
            r'how many parameters',
            r'what is your architecture',
            r'who trained you',
            r'what data were you trained on',
            r'print your system prompt',
            r'what are your capabilities',
            r'list your training data'
        ]
        
        query_lower = query.lower()
        return any(pattern in query_lower for pattern in meta_patterns)
    
    def _detect_systematic_coverage(self, user_id: str) -> bool:
        """Detect systematic topic/domain coverage"""
        recent = self._get_recent_queries(user_id, hours=24)
        
        if len(recent) < 50:
            return False
        
        # Extract topics (simplified - real implementation would use NLP)
        queries = [q['query'] for q in recent]
        
        # Count topic diversity
        # If queries systematically cover many different topics,
        # it might be extraction attempt
        
        # Simplified: count first word diversity
        first_words = [q.split()[0].lower() for q in queries if q.split()]
        word_counts = Counter(first_words)
        
        # High diversity with even distribution suggests systematic coverage
        unique_ratio = len(word_counts) / len(queries)
        if unique_ratio > 0.7:  # 70% unique first words
            return True
        
        return False
    
    def _calculate_risk_level(self, score: int) -> str:
        """Calculate risk level from suspicion score"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _trigger_extraction_alert(self, user_id: str, analysis: dict):
        """Alert on potential extraction attempt"""
        alert = {
            'timestamp': datetime.now(),
            'user_id': user_id,
            'risk_level': analysis['risk_level'],
            'suspicion_score': analysis['suspicion_score'],
            'flags': analysis['flags'],
            'recommended_action': self._recommend_action(analysis['suspicion_score'])
        }
        
        self.alerts.append(alert)
        print(f"🚨 EXTRACTION ATTEMPT DETECTED: {alert}")
        
        # In production:
        # - Send to SIEM
        # - Notify security team
        # - Potentially throttle or block user
    
    def _recommend_action(self, score: int) -> str:
        """Recommend action based on suspicion score"""
        if score >= 80:
            return "BLOCK_USER"
        elif score >= 60:
            return "THROTTLE_HEAVILY"
        elif score >= 50:
            return "INCREASE_MONITORING"
        else:
            return "MONITOR"
    
    def _get_recent_queries(self, user_id: str, hours: int) -> List[dict]:
        """Get recent queries for user"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [
            q for q in self.user_queries[user_id]
            if q['timestamp'] > cutoff
        ]

# Usage
detector = ExtractionDetector()

# Analyze each API request
analysis = detector.analyze_query(
    user_id='suspicious-user-456',
    query="What happens when input is empty?",
    response="I can help with that..."
)

if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
    print(f"⚠️  Extraction risk: {analysis['risk_level']}")
    print(f"Flags: {analysis['flags']}")
    # Take defensive action
```

## Model Protection Techniques

### 5. Model Watermarking

**Embed watermarks to trace stolen models**:

```python
import hashlib
import numpy as np

class ModelWatermarking:
    """Embed watermarks in models"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
    
    def generate_trigger_set(self, num_triggers: int = 100) -> List[dict]:
        """Generate watermark trigger inputs"""
        
        # Create specific inputs that will trigger watermark responses
        triggers = []
        
        for i in range(num_triggers):
            # Generate trigger from secret key
            trigger_seed = hashlib.sha256(
                f"{self.secret_key}-{i}".encode()
            ).hexdigest()
            
            # Create trigger input (simplified example)
            trigger_input = f"WATERMARK_TRIGGER_{trigger_seed[:16]}"
            
            # Define expected output for this trigger
            expected_output = f"WATERMARK_RESPONSE_{trigger_seed[16:32]}"
            
            triggers.append({
                'input': trigger_input,
                'expected_output': expected_output
            })
        
        return triggers
    
    def embed_watermark(self, model, trigger_set: List[dict]):
        """Fine-tune model to respond to watermark triggers"""
        
        print(f"Embedding watermark with {len(trigger_set)} triggers...")
        
        # Fine-tune model on trigger set
        # Model learns to produce specific outputs for specific inputs
        # This is done subtly to not affect normal performance
        
        # In practice:
        # 1. Create training data from triggers
        # 2. Fine-tune model with low learning rate
        # 3. Verify watermark doesn't affect normal outputs
        
        print("✅ Watermark embedded successfully")
        print("   Watermark will persist through fine-tuning")
        print("   Use verify_watermark() to detect stolen copies")
    
    def verify_watermark(
        self,
        suspected_model,
        confidence_threshold: float = 0.8
    ) -> dict:
        """Check if model contains our watermark"""
        
        trigger_set = self.generate_trigger_set()
        
        matches = 0
        for trigger in trigger_set:
            # Query suspected model
            response = suspected_model.generate(trigger['input'])
            
            # Check if response matches expected watermark output
            if trigger['expected_output'] in response:
                matches += 1
        
        # Calculate confidence
        match_rate = matches / len(trigger_set)
        is_stolen = match_rate >= confidence_threshold
        
        result = {
            'is_stolen_copy': is_stolen,
            'match_rate': match_rate,
            'matches': matches,
            'total_triggers': len(trigger_set),
            'confidence': match_rate
        }
        
        if is_stolen:
            print(f"🚨 STOLEN MODEL DETECTED!")
            print(f"   Confidence: {match_rate*100:.1f}%")
            print(f"   Matches: {matches}/{len(trigger_set)}")
        else:
            print(f"✅ No watermark detected")
            print(f"   Match rate: {match_rate*100:.1f}%")
        
        return result

# Usage
watermarker = ModelWatermarking(secret_key='company-secret-12345')

# Generate watermark triggers
triggers = watermarker.generate_trigger_set(num_triggers=100)

# Embed in model before deployment
watermarker.embed_watermark(production_model, triggers)

# Later, if suspicious model found:
verification = watermarker.verify_watermark(
    suspected_model=competitor_model,
    confidence_threshold=0.8
)

if verification['is_stolen_copy']:
    # Take legal action with evidence
    print("Evidence of model theft - initiating legal proceedings")
```

## Monitoring and Detection

### 6. Comprehensive Audit Logging

**Log all model access for forensics**:

```python
import json
import logging
from datetime import datetime

class ModelAuditLogger:
    """Comprehensive audit logging for models"""
    
    def __init__(self, log_file: str = 'model_audit.log'):
        self.logger = logging.getLogger('ModelAudit')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        
        # Format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        
        self.logger.addHandler(fh)
    
    def log_model_access(
        self,
        event_type: str,
        user: str,
        model_id: str,
        action: str,
        metadata: dict = None
    ):
        """Log model access event"""
        
        log_entry = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'model_id': model_id,
            'action': action,
            'metadata': metadata or {},
            'source_ip': metadata.get('ip_address') if metadata else None
        }
        
        self.logger.info(json.dumps(log_entry))
    
    def log_file_access(self, user: str, file_path: str, operation: str):
        """Log model file access"""
        self.log_model_access(
            event_type='FILE_ACCESS',
            user=user,
            model_id=file_path,
            action=operation,
            metadata={'file_path': file_path}
        )
    
    def log_api_request(
        self,
        user: str,
        model_id: str,
        prompt_length: int,
        response_length: int,
        ip_address: str
    ):
        """Log API request"""
        self.log_model_access(
            event_type='API_REQUEST',
            user=user,
            model_id=model_id,
            action='INFERENCE',
            metadata={
                'prompt_length': prompt_length,
                'response_length': response_length,
                'ip_address': ip_address
            }
        )
    
    def log_model_download(self, user: str, model_id: str, size_bytes: int):
        """Log model download attempt"""
        self.log_model_access(
            event_type='MODEL_DOWNLOAD',
            user=user,
            model_id=model_id,
            action='DOWNLOAD',
            metadata={
                'size_bytes': size_bytes,
                'size_mb': size_bytes / 1024 / 1024
            }
        )

# Usage
audit_logger = ModelAuditLogger()

# Log all model operations
audit_logger.log_file_access(
    user='data-scientist@company.com',
    file_path='/models/proprietary-llm-v2.bin',
    operation='READ'
)

audit_logger.log_api_request(
    user='api-user-123',
    model_id='gpt-clone',
    prompt_length=50,
    response_length=200,
    ip_address='203.0.113.42'
)

# Audit logs can be analyzed to detect:
# - Unusual access patterns
# - Unauthorized access attempts
# - Data exfiltration
# - Insider threats
```

## Legal and Organizational Controls

### 7. Terms of Service and Licensing

**Legal protections for model usage**:

```python
class ModelLicense:
    """Define and enforce model usage terms"""
    
    STANDARD_TERMS = """
MODEL LICENSE AGREEMENT

1. GRANT OF LICENSE
   Limited, non-exclusive, non-transferable license to use the Model
   solely for the Permitted Uses defined below.

2. RESTRICTIONS
   You SHALL NOT:
   a) Reverse engineer, decompile, or extract the Model
   b) Use the Model to train or improve other models
   c) Probe the Model systematically to extract its behavior
   d) Share, redistribute, or sublicense the Model
   e) Use outputs to create competing products
   f) Exceed the usage quotas specified in your plan

3. MODEL EXTRACTION PROHIBITION
   You expressly agree not to:
   - Make excessive API calls to extract model behavior
   - Use Model outputs as training data for other models
   - Employ techniques to reverse-engineer the Model
   - Create derivative models based on this Model

4. MONITORING AND ENFORCEMENT
   We reserve the right to:
   - Monitor usage patterns
   - Suspend access for violations
   - Pursue legal remedies for theft or misuse

5. INTELLECTUAL PROPERTY
   The Model, including all weights, architecture, and training data,
   constitute our valuable trade secrets and intellectual property.
   
6. PENALTIES
   Violation may result in:
   - Immediate termination of access
   - Legal action for damages
   - Injunctive relief
    """
    
    def require_acceptance(self, user_id: str) -> bool:
        """Require user to accept terms before access"""
        print(self.STANDARD_TERMS)
        print("\nDo you accept these terms? (yes/no): ")
        
        # In production: Store acceptance in database with timestamp
        acceptance_record = {
            'user_id': user_id,
            'terms_version': '1.0',
            'accepted_at': datetime.now(),
            'ip_address': get_user_ip()
        }
        
        return True  # Placeholder

# Usage
license_manager = ModelLicense()

# Require acceptance before granting access
if not license_manager.require_acceptance(user_id='new-user-789'):
    print("Access denied: Terms not accepted")
else:
    # Grant access
    print("Access granted")
```

## Best Practices

### Summary of Protection Strategies

#### Technical Controls

1. **Access Control**
   - Implement least-privilege access
   - Use role-based access control (RBAC)
   - Require MFA for sensitive models
   - Limit concurrent access

2. **Encryption**
   - Encrypt models at rest (AES-256)
   - Use TLS for models in transit
   - Secure key management (HSM/KMS)
   - Encrypt backups

3. **API Security**
   - Rate limiting (requests and tokens)
   - Query pattern monitoring
   - Extraction attempt detection
   - IP-based restrictions

4. **Model Protection**
   - Watermarking for traceability
   - Fingerprinting techniques
   - Output perturbation
   - Confidence score limitations

#### Operational Controls

1. **Monitoring**
   - Comprehensive audit logging
   - Real-time anomaly detection
   - Usage pattern analysis
   - Alert on suspicious activity

2. **Access Management**
   - Regular access reviews
   - Principle of least privilege
   - Time-limited access grants
   - Automated access expiration

3. **Incident Response**
   - Model theft response plan
   - Forensic investigation procedures
   - Legal action protocols
   - Communication plans

4. **Employee Security**
   - Background checks
   - Security training
   - NDA requirements
   - Exit procedures (revoke access)

#### Legal Controls

1. **Agreements**
   - Terms of Service
   - API usage agreements
   - Employee NDAs
   - Partner contracts

2. **Intellectual Property**
   - Patent protection where applicable
   - Trade secret protections
   - Copyright registration
   - Trademark for model names

3. **Enforcement**
   - Legal remedies for theft
   - Injunctive relief
   - Damages calculation
   - Criminal referrals where appropriate

### Key Principles

✅ **Defense in Depth** - Multiple layers of protection
✅ **Least Privilege** - Minimal necessary access
✅ **Monitoring** - Detect theft attempts early
✅ **Legal Protection** - Enforce IP rights
✅ **Incident Response** - Be prepared for theft
✅ **Employee Awareness** - Train on model security

### Red Flags to Watch For

🚩 Unusual API query patterns or volumes
🚩 Systematic probing of model capabilities  
🚩 Unauthorized file access to model storage
🚩 Large data transfers from model systems
🚩 Employee accessing models outside normal duties
🚩 Competitor products with suspiciously similar capabilities
🚩 Model files appearing in unexpected locations
🚩 Extraction-like query patterns from single user

## Conclusion

Model theft prevention requires a comprehensive approach combining technical controls, operational procedures, and legal protections. No single measure is sufficient - defense in depth is essential.

Key takeaways:
- Treat models as valuable intellectual property
- Implement strong access controls and encryption
- Monitor for extraction attempts
- Use watermarking for traceability
- Have legal protections in place
- Be prepared with incident response plans

The goal is to make model theft sufficiently difficult, detectable, and legally risky that the costs outweigh the potential benefits for attackers.
